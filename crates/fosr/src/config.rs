use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct Configuration {
    pub metadata: Metadata,
    pub hosts: Vec<Host>,
}

#[derive(Deserialize, Debug)]
pub struct Metadata {
    pub title: String,
    pub desc: Option<String>,
    pub author: Option<String>,
    pub date: Option<String>,
    pub version: Option<String>,
    pub format: Option<u64>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum HostType {
    Server,
    User,
}

#[derive(Deserialize, Debug)]
pub struct Host {
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub activity: Option<f64>,
    #[serde(rename = "type")]
    pub host_type: Option<HostType>,
    pub interfaces: Vec<Interface>,
}

#[derive(Deserialize, Debug)]
pub struct Interface {
    pub mac_addr: Option<String>,
    pub services: Option<Vec<String>>,
    pub ip_addr: String,
}

pub fn import_config(config_path: &str) -> Configuration {
    let config: Configuration =
        serde_yaml::from_str(&config_path).expect("Cannot parse the configuration file");
    log::info!("\"{}\" successfully loaded", config.metadata.title);
    config
}
