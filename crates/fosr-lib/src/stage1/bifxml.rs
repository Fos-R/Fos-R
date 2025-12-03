use crate::stage1::*;

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
#[allow(unused)]
pub struct Network {
    name: String,     // TODO paramétrer dans agrum
    property: String, // learning software
    pub variable: Vec<Variable>,
    pub definition: Vec<Definition>,
}

pub fn from_str(string: &str) -> Result<Network, String> {
    Ok(serde_xml_rs::from_str::<Bif>(string)
        .map_err(|_| "Cannot parse the BIF file".to_string())?
        .network)
    // let mut network = serde_xml_rs::from_str::<Bif>(string).unwrap().network;
    // for def in network.definition.iter_mut() {
    //     if let Some(mut given) = def.given.as_mut() {
    //         given.reverse();
    //     }
    // }
    // network
}

impl Network {
    /// Apply a suffix to the variables of "other" and merge the two networks
    pub fn merge(&mut self, mut other: Network, proto: Protocol) {
        let outer_variable: Vec<String> = self.variable.iter().map(|v| v.name.clone()).collect();
        let suffix = " ".to_string() + &proto.to_string();
        for v in other.variable.iter_mut() {
            // log::info!("Suffix to {}", &v.name);
            v.name = v.name.clone() + &suffix;
            v.proto_specific = Some(proto);
        }
        for d in other.definition.iter_mut() {
            d.variable = d.variable.clone() + &suffix;
            // if the parent is exist in the "self" network, keep it as is
            // otherwise, apply the suffix
            if d.given.is_some() {
                for v in d.given.as_mut().unwrap().iter_mut() {
                    if !outer_variable.contains(v) {
                        *v = v.clone() + &suffix;
                    }
                }
            }
        }

        self.variable.append(&mut other.variable);
        self.definition.append(&mut other.definition);
        // log::info!("{:?}", self.variable);
        // log::info!("{:?}", self.definition.iter().map(|d| d.given.clone()));
    }
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "UPPERCASE")]
#[allow(unused)]
pub struct Variable {
    pub name: String,
    property: Vec<String>,
    pub outcome: Vec<String>,
    pub proto_specific: Option<Protocol>, // not present in the format but convenient
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "UPPERCASE")]
pub struct Definition {
    #[serde(rename = "FOR")]
    pub variable: String,
    pub given: Option<Vec<String>>,
    pub table: String,
}
