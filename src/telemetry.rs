use std::borrow::Cow;

use thiserror::Error;
use tokio::sync::mpsc;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("custom tracing level has no verbosity")]
    CustomHasNoVerbosity,
    #[error("error while updating tracing level")]
    UpdateTracingLevel(#[from] mpsc::error::SendError<TracingLevel>),
}

#[derive(Clone, Debug)]
pub struct Client {
    app_modules: Vec<&'static str>,
    tracing_level: TracingLevel,
    tracing_level_tx: mpsc::Sender<TracingLevel>,
}

impl Client {
    #[must_use]
    pub fn new(
        app_modules: Vec<&'static str>,
        tracing_level: TracingLevel,
        tracing_level_tx: mpsc::Sender<TracingLevel>,
    ) -> Self {
        Self {
            app_modules,
            tracing_level,
            tracing_level_tx,
        }
    }

    pub async fn set_verbosity(&mut self, updated: Verbosity) -> Result<(), ClientError> {
        match self.tracing_level {
            TracingLevel::Verbosity {
                ref mut verbosity, ..
            } => {
                *verbosity = updated;
            }
            TracingLevel::Custom(_) => {
                self.tracing_level = TracingLevel::new(updated, Some(self.app_modules.as_slice()));
            }
        }

        self.tracing_level_tx
            .send(self.tracing_level.clone())
            .await?;
        Ok(())
    }

    pub async fn set_custom_tracing(
        &mut self,
        directives: impl Into<String>,
    ) -> Result<(), ClientError> {
        let updated = TracingLevel::custom(directives);
        self.tracing_level = updated;
        self.tracing_level_tx
            .send(self.tracing_level.clone())
            .await?;
        Ok(())
    }

    pub async fn increase_verbosity(&mut self) -> Result<(), ClientError> {
        match self.tracing_level {
            TracingLevel::Verbosity { verbosity, .. } => {
                let updated = verbosity.increase();
                self.set_verbosity(updated).await
            }
            TracingLevel::Custom(_) => Err(ClientError::CustomHasNoVerbosity),
        }
    }

    pub async fn decrease_verbosity(&mut self) -> Result<(), ClientError> {
        match self.tracing_level {
            TracingLevel::Verbosity { verbosity, .. } => {
                let updated = verbosity.decrease();
                self.set_verbosity(updated).await
            }
            TracingLevel::Custom(_) => Err(ClientError::CustomHasNoVerbosity),
        }
    }
}

#[derive(Clone, Debug)]
pub enum TracingLevel {
    Verbosity {
        verbosity: Verbosity,
        app_modules: Option<Vec<Cow<'static, str>>>,
    },
    Custom(String),
}

impl TracingLevel {
    pub fn new(verbosity: Verbosity, app_modules: Option<impl IntoAppModules>) -> Self {
        Self::Verbosity {
            verbosity,
            app_modules: app_modules.map(IntoAppModules::into_app_modules),
        }
    }

    pub fn custom(directives: impl Into<String>) -> Self {
        Self::Custom(directives.into())
    }
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd)]
pub enum Verbosity {
    InfoAll,
    DebugAppAndInfoAll,
    TraceAppAndInfoAll,
    TraceAppAndDebugAll,
    TraceAll,
}

impl Verbosity {
    #[must_use]
    pub fn increase(self) -> Self {
        self.as_usize().saturating_add(1).into()
    }

    #[must_use]
    pub fn decrease(self) -> Self {
        self.as_usize().saturating_sub(1).into()
    }

    fn as_usize(self) -> usize {
        self.into()
    }
}

impl Default for Verbosity {
    fn default() -> Self {
        Self::InfoAll
    }
}

impl From<usize> for Verbosity {
    fn from(value: usize) -> Self {
        match value {
            0 => Self::InfoAll,
            1 => Self::DebugAppAndInfoAll,
            2 => Self::TraceAppAndInfoAll,
            3 => Self::TraceAppAndDebugAll,
            _ => Self::TraceAll,
        }
    }
}

impl From<Verbosity> for usize {
    fn from(value: Verbosity) -> Self {
        match value {
            Verbosity::InfoAll => 0,
            Verbosity::DebugAppAndInfoAll => 1,
            Verbosity::TraceAppAndInfoAll => 2,
            Verbosity::TraceAppAndDebugAll => 3,
            Verbosity::TraceAll => 4,
        }
    }
}

pub trait IntoAppModules {
    fn into_app_modules(self) -> Vec<Cow<'static, str>>;
}

impl IntoAppModules for Vec<String> {
    fn into_app_modules(self) -> Vec<Cow<'static, str>> {
        self.into_iter().map(Cow::Owned).collect()
    }
}

impl IntoAppModules for Vec<&'static str> {
    fn into_app_modules(self) -> Vec<Cow<'static, str>> {
        self.into_iter().map(Cow::Borrowed).collect()
    }
}

impl IntoAppModules for &[&'static str] {
    fn into_app_modules(self) -> Vec<Cow<'static, str>> {
        self.iter().map(|e| Cow::Borrowed(*e)).collect()
    }
}
