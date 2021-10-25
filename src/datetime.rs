use chrono::{DateTime, FixedOffset};
use serde::{de, Deserialize, Deserializer, Serializer};

pub(crate) fn deserialize_date_time<'de, D>(
    deserializer: D,
) -> Result<DateTime<FixedOffset>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    DateTime::parse_from_rfc3339(&s).map_err(de::Error::custom)
}

pub(crate) fn serialize_date_time<S>(
    date_time: &DateTime<FixedOffset>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let s: String = date_time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    serializer.serialize_str(&s)
}
