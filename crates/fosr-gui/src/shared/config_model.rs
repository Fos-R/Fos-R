use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Configuration {
    #[serde(default)]
    pub metadata: Metadata,

    #[serde(default)]
    pub hosts: Vec<Host>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Metadata {
    pub title: Option<String>,
    pub desc: Option<String>,
    pub author: Option<String>,
    pub date: Option<String>,
    pub version: Option<String>,
    pub format: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Host {
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub usage: Option<f32>,
    pub r#type: Option<String>,

    #[serde(default)]
    pub client: Vec<String>,

    #[serde(default)]
    pub interfaces: Vec<Interface>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Interface {
    pub mac_addr: Option<String>,

    // Mandatory dans ton YAML -> String (si absent, parsing échoue)
    pub ip_addr: String,

    #[serde(default)]
    pub services: Vec<String>,
}
