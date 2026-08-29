use serde::Deserialize;

// BIFXML format

#[derive(Deserialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
// The root element
struct Bif {
    network: Network,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "UPPERCASE")]
pub struct Network {
    #[allow(unused)]
    name: String,
    #[allow(unused)]
    property: String, // learning software
    pub variable: Vec<Variable>,
    pub definition: Vec<Definition>,
}

pub fn from_str(string: &str) -> Result<Network, String> {
    Ok(serde_xml_rs::from_str::<Bif>(string)
        .map_err(|e| format!("Cannot parse the BIF file: {e}"))?
        .network)
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub struct Variable {
    pub name: String,
    #[allow(unused)]
    property: Vec<String>,
    pub outcome: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub struct Definition {
    #[serde(rename = "FOR")]
    pub variable: String,
    pub given: Option<Vec<String>>,
    pub table: String,
}
