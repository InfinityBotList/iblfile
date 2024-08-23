use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Cursor;
use std::sync::LazyLock;

pub static FORMAT_VERSION_MAP: LazyLock<DashMap<String, Vec<Format>>> = LazyLock::new(DashMap::new);

#[derive(Serialize, Deserialize)]
pub struct Meta {
    #[serde(rename = "c")]
    pub created_at: DateTime<Utc>,
    #[serde(rename = "p")]
    pub protocol: String,
    #[serde(rename = "v", skip_serializing_if = "Option::is_none")]
    pub format_version: Option<String>,
    #[serde(rename = "t")]
    pub r#type: String,
    #[serde(rename = "m", skip_serializing_if = "Option::is_none")]
    pub extra_metadata: Option<HashMap<String, String>>,
}

pub type GetExtended = fn(
    &HashMap<String, Cursor<Vec<u8>>>,
    &Meta,
) -> Result<HashMap<String, serde_json::Value>, crate::Error>;

/// A helper struct to register/store a format
#[derive(Clone)]
pub struct Format {
    pub format: String,
    pub version: String,
    pub get_extended: GetExtended,
}

pub fn register_format(ns: &str, formats: Vec<Format>) {
    FORMAT_VERSION_MAP
        .entry(ns.to_string())
        .or_default()
        .extend(formats);
}

pub fn get_format(format: &str) -> Result<Format, crate::Error> {
    let split_format: Vec<&str> = format.split('.').collect();

    if split_format.len() < 2 {
        return Err(format!("format does not have a namespace: {}", format).into());
    }

    let ns = split_format[0];
    let name = split_format[1..].join(".");

    let fvns = FORMAT_VERSION_MAP
        .get(ns)
        .ok_or_else(|| format!("namespace not found: {}", ns))?;

    fvns.iter()
        .find(|fv| fv.format == name)
        .cloned()
        .ok_or_else(|| format!("format not found in namespace: {}", format).into())
}

pub fn condensed_format(ns: &str, format: &str) -> String {
    format!("{}.{}", ns, format)
}
