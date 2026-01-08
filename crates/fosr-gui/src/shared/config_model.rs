use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Configuration {
    #[serde(default)]
    pub metadata: Metadata,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<Host>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Metadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Host {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub client: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<Interface>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Interface {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_addr: Option<String>,

    // Mandatory dans ton YAML -> String (si absent, parsing échoue)
    pub ip_addr: String,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<String>,
}
