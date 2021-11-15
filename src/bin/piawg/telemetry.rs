use std::{borrow::Cow, env, io, ops::Deref};

use color_eyre::Result;
use derive_builder::Builder;
use piawg::telemetry::{Client, TracingLevel, Verbosity};
use tokio::sync::mpsc;
use tracing::{debug, info, warn, Subscriber};
use tracing_subscriber::{
    fmt::{self, format::FmtSpan, MakeWriter},
    prelude::*,
    reload,
    util::SubscriberInitExt,
    EnvFilter, Registry,
};

#[derive(Clone, Builder, Debug, Default)]
pub struct Config {
    #[builder(setter(into), default = r#"env!("CARGO_PKG_NAME").to_string()"#)]
    service_name: String,

    #[builder(setter(into), default = r#"env!("CARGO_PKG_VERSION").to_string()"#)]
    service_version: String,

    #[builder(setter(into))]
    service_namespace: String,

    #[builder(default)]
    app_modules: Vec<&'static str>,

    #[builder(
        setter(into, strip_option),
        default = "self.default_log_env_var_prefix()?"
    )]
    log_env_var_prefix: Option<String>,

    #[builder(setter(into, strip_option), default = "self.default_log_env_var()?")]
    log_env_var: Option<String>,

    #[builder(
        setter(into, strip_option),
        default = "self.default_secondary_log_env_var()"
    )]
    secondary_log_env_var: Option<String>,
}

impl Config {
    #[must_use]
    pub fn builder() -> ConfigBuilder {
        ConfigBuilder::default()
    }
}

type EnvLayerHandle = reload::Handle<Option<EnvFilter>, Registry>;

pub fn init(config: Config) -> Result<Client> {
    inner_init(config, io::stdout)
}

#[cfg(unix)]
pub fn start_tracing_level_signal_handler_task(client: &Client) -> io::Result<()> {
    use tokio::signal::unix;

    let user_defined1 = unix::signal(unix::SignalKind::user_defined1())?;
    let user_defined2 = unix::signal(unix::SignalKind::user_defined2())?;
    drop(tokio::spawn(tracing_level_signal_handler_task(
        client.clone(),
        user_defined1,
        user_defined2,
    )));
    Ok(())
}

pub fn init_with_writer<W>(config: Config, make_writer: W) -> Result<Client>
where
    W: MakeWriter + Send + Sync + 'static,
{
    inner_init(config, make_writer)
}

fn inner_init<W>(config: Config, make_writer: W) -> Result<Client>
where
    W: MakeWriter + Send + Sync + 'static,
{
    let tracing_level = default_tracing_level(&config);
    let (subscriber, env_handle) = tracing_subscriber(&tracing_level, make_writer)?;
    subscriber.try_init()?;
    let telemetry_client = start_telemetry_update_tasks(config, tracing_level, env_handle);

    Ok(telemetry_client)
}

fn default_tracing_level(config: &Config) -> TracingLevel {
    if let Some(log_env_var) = config.log_env_var.as_deref() {
        if let Ok(value) = env::var(log_env_var.to_uppercase()) {
            if !value.is_empty() {
                return TracingLevel::custom(value);
            }
        }
    }
    if let Some(log_env_var) = config.secondary_log_env_var.as_deref() {
        if let Ok(value) = env::var(log_env_var.to_uppercase()) {
            if !value.is_empty() {
                return TracingLevel::custom(value);
            }
        }
    }

    TracingLevel::new(Verbosity::default(), Some(config.app_modules.as_ref()))
}

fn tracing_subscriber<W>(
    tracing_level: &TracingLevel,
    make_writer: W,
) -> Result<(impl Subscriber + Send + Sync, EnvLayerHandle)>
where
    W: MakeWriter + Send + Sync + 'static,
{
    let directives = TracingDirectives::from(tracing_level);
    let env_filter = EnvFilter::try_new(directives.as_str())?;
    let (env_filter_layer, env_handle) = reload::Layer::new(Some(env_filter));

    let registry = Registry::default().with(env_filter_layer).with(
        fmt::layer()
            .with_thread_ids(true)
            .with_thread_names(true)
            .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
            .with_writer(make_writer),
    );

    Ok((registry, env_handle))
}

fn start_telemetry_update_tasks(
    config: Config,
    tracing_level: TracingLevel,
    env_handle: EnvLayerHandle,
) -> Client {
    let (tracing_level_tx, tracing_level_rx) = mpsc::channel(2);
    drop(tokio::spawn(update_tracing_level_task(
        env_handle,
        tracing_level_rx,
    )));

    Client::new(config.app_modules, tracing_level, tracing_level_tx)
}

async fn update_tracing_level_task(handle: EnvLayerHandle, mut rx: mpsc::Receiver<TracingLevel>) {
    while let Some(tracing_level) = rx.recv().await {
        if let Err(err) = update_tracing_level(&handle, tracing_level) {
            warn!(error = ?err, "failed to update tracing level, using prior value");
            continue;
        }
    }
    debug!("update_tracing_level_task received closed channel, ending task");
}

fn update_tracing_level(handle: &EnvLayerHandle, tracing_level: TracingLevel) -> Result<()> {
    let directives = TracingDirectives::from(tracing_level);
    let updated = EnvFilter::try_new(directives.as_str())?;

    handle.modify(|layer| {
        layer.replace(updated);
    })?;
    info!("updated tracing levels to: {:?}", directives.as_str());

    Ok(())
}

#[cfg(unix)]
async fn tracing_level_signal_handler_task(
    mut client: Client,
    mut user_defined1: tokio::signal::unix::Signal,
    mut user_defined2: tokio::signal::unix::Signal,
) {
    use tracing::trace;

    loop {
        tokio::select! {
            _ = user_defined1.recv() => {
                if let Err(err) = client.increase_verbosity().await {
                    warn!(error = ?err, "error while trying to increase verbosity");
                }
            }
            _ = user_defined2.recv() => {
                if let Err(err) = client.decrease_verbosity().await {
                    warn!(error = ?err, "error while trying to decrease verbosity");
                }
            }
            else => {
                // All other arms are closed, nothing left to do but return
                trace!("returning from tracing level signal handler with all select arms closed");
            }
        }
    }
}

impl ConfigBuilder {
    fn default_log_env_var_prefix(&self) -> Result<Option<String>, ConfigBuilderError> {
        match &self.service_namespace {
            Some(service_namespace) => Ok(Some(service_namespace.to_uppercase())),
            None => Err(ConfigBuilderError::ValidationError(
                "service_namespace must be set".to_string(),
            )),
        }
    }

    fn default_log_env_var(&self) -> Result<Option<String>, ConfigBuilderError> {
        match (&self.log_env_var_prefix, &self.service_name) {
            (Some(Some(prefix)), Some(service_name)) => Ok(Some(format!(
                "{}_{}_LOG",
                prefix.to_uppercase(),
                service_name.to_uppercase()
            ))),
            (Some(None) | None, Some(service_name)) => {
                Ok(Some(format!("{}_LOG", service_name.to_uppercase())))
            }
            (None | Some(_), None) => Err(ConfigBuilderError::ValidationError(
                "service_name must be set".to_string(),
            )),
        }
    }

    fn default_secondary_log_env_var(&self) -> Option<String> {
        match &self.log_env_var_prefix {
            Some(Some(prefix)) => Some(format!("{}_LOG", prefix.to_uppercase())),
            Some(None) | None => None,
        }
    }
}

struct TracingDirectives(Cow<'static, str>);

impl TracingDirectives {
    fn new(verbosity: Verbosity, app_modules: &Option<Vec<Cow<'static, str>>>) -> Self {
        let directives = match verbosity {
            Verbosity::InfoAll => match &app_modules {
                Some(mods) => Cow::Owned(format!(
                    "{},{}",
                    "info",
                    mods.iter()
                        .map(|m| format!("{}=info", m))
                        .collect::<Vec<_>>()
                        .join(",")
                )),
                None => Cow::Borrowed("info"),
            },
            Verbosity::DebugAppAndInfoAll => match &app_modules {
                Some(mods) => Cow::Owned(format!(
                    "{},{}",
                    "info",
                    mods.iter()
                        .map(|m| format!("{}=debug", m))
                        .collect::<Vec<_>>()
                        .join(",")
                )),
                None => Cow::Borrowed("debug"),
            },
            Verbosity::TraceAppAndInfoAll => match &app_modules {
                Some(mods) => Cow::Owned(format!(
                    "{},{}",
                    "info",
                    mods.iter()
                        .map(|m| format!("{}=trace", m))
                        .collect::<Vec<_>>()
                        .join(",")
                )),
                None => Cow::Borrowed("trace"),
            },
            Verbosity::TraceAppAndDebugAll => match &app_modules {
                Some(mods) => Cow::Owned(format!(
                    "{},{}",
                    "debug",
                    mods.iter()
                        .map(|m| format!("{}=trace", m))
                        .collect::<Vec<_>>()
                        .join(",")
                )),
                None => Cow::Borrowed("trace"),
            },
            Verbosity::TraceAll => match &app_modules {
                Some(mods) => Cow::Owned(format!(
                    "{},{}",
                    "trace",
                    mods.iter()
                        .map(|m| format!("{}=trace", m))
                        .collect::<Vec<_>>()
                        .join(",")
                )),
                None => Cow::Borrowed("trace"),
            },
        };

        Self(directives)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_ref()
    }
}

impl From<TracingLevel> for TracingDirectives {
    fn from(value: TracingLevel) -> Self {
        match value {
            TracingLevel::Verbosity {
                verbosity,
                app_modules,
            } => Self::new(verbosity, &app_modules),
            TracingLevel::Custom(custom) => custom.into(),
        }
    }
}

impl From<&TracingLevel> for TracingDirectives {
    fn from(value: &TracingLevel) -> Self {
        match value {
            TracingLevel::Verbosity {
                verbosity,
                app_modules,
            } => Self::new(*verbosity, app_modules),
            TracingLevel::Custom(custom) => custom.clone().into(),
        }
    }
}

impl From<String> for TracingDirectives {
    fn from(value: String) -> Self {
        Self(Cow::Owned(value))
    }
}

impl From<&'static str> for TracingDirectives {
    fn from(value: &'static str) -> Self {
        Self(Cow::Borrowed(value))
    }
}

impl Deref for TracingDirectives {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}
