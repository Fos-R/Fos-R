use crate::{stage1, stage2, stage3};
#[allow(unused_imports)]
use include_dir::include_dir;
#[allow(unused_imports)]
use include_dir::{Dir, DirEntry};
use std::ffi::OsStr;
use std::fs;
use std::path::Path;

/// The source of models
pub enum ModelsSource {
    #[cfg(feature = "models_cicids17")]
    /// Models based on the CICIDS2017 dataset
    CICIDS17,
    #[cfg(feature = "models_cupid")]
    /// Models based on the CUPID dataset
    CUPID,
    #[cfg(feature = "models_dedale")]
    /// Models based on the DEDALE dataset
    DEDALE,
    /// Models defined by the user
    UserDefined(String),
}

/// The models
pub struct Models {
    /// The time model of stage 0
    pub time_bins: stage1::TimeModel,
    /// The Bayesian network of stage 1
    pub bn: stage2::bayesian_networks::BayesianModel,
    /// The automata of stage 2
    pub automata: stage3::tadam::AutomataLibrary,
}

impl Models {
    pub fn from_source(source: ModelsSource) -> Result<Self, String> {
        Ok(Models {
            automata: stage3::tadam::AutomataLibrary::from_source(&source)?,
            bn: stage2::bayesian_networks::BayesianModel::from_source(&source)?,
            time_bins: stage1::TimeModel::from_source(&source)?,
        })
    }

    // pub fn with_network(mut self, path: &str) -> Result<Self, String> {
    //     let network = network::import_network(
    //         &fs::read_to_string(Path::new(path))
    //             .map_err(|e| format!("Cannot open the network file: {e}"))?,
    //     );
    //     self.bn.apply_network(&network)?;
    //     Ok(self)
    // }

    // pub fn with_string_network(mut self, network: &str) -> Result<Self, String> {
    //     let network = network::import_network(network);
    //     self.bn.apply_network(&network)?;
    //     Ok(self)
    // }
}

impl ModelsSource {
    pub(crate) fn get_automata(&self) -> std::io::Result<Vec<String>> {
        match &self {
            #[cfg(feature = "models_cicids17")]
            ModelsSource::CICIDS17 => Ok(
                // #[cfg(debug_assertions)]
                {
                    let d: Dir =
                        include_dir!("$CARGO_MANIFEST_DIR/default_models/cicids17/automata/");
                    d.find("**/*.json")
                        .unwrap()
                        .filter_map(|e: &DirEntry| e.as_file())
                        .filter(|e| !e.path().to_str().unwrap().ends_with("-language.json"))
                        .inspect(|e| {
                            log::debug!("Including automata file {:?}", e.path());
                        })
                        .map(|f: &include_dir::File| f.contents_utf8().unwrap().to_string())
                        .collect()
                },
                // #[cfg(not(debug_assertions))]
                // {
                //     vec![
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cicids17/automata/dce_rpc,gssapi,krb-SF.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cicids17/automata/dce_rpc,gssapi,smb-SF.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cicids17/automata/dce_rpc-SF.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cicids17/automata/dns.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cicids17/automata/ftp-data-SF.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cicids17/automata/ftp-SF.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cicids17/automata/gssapi,krb,smb-RST.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cicids17/automata/gssapi,ntlm,smb-RST.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cicids17/automata/http-RST.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cicids17/automata/http-S0.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cicids17/automata/http-SF.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cicids17/automata/krb.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cicids17/automata/krb_tcp-RST.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cicids17/automata/ldap_tcp-RST.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cicids17/automata/ldap_udp.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cicids17/automata/ntp.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cicids17/automata/ssl-REJ.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cicids17/automata/ssl-RST.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cicids17/automata/ssl-S0.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cicids17/automata/ssl-SF.json",
                //             1
                //         ))
                //         .unwrap(),
                //     ]
                // },
            ),
            #[cfg(feature = "models_cupid")]
            ModelsSource::CUPID => Ok(
                // #[cfg(debug_assertions)]
                {
                    let d: Dir =
                        include_dir!("$CARGO_MANIFEST_DIR/default_models/cupid/automata/");
                    d.find("**/*.json")
                        .unwrap()
                        .filter_map(|e: &DirEntry| e.as_file())
                        .filter(|e| !e.path().to_str().unwrap().ends_with("-language.json"))
                        .inspect(|e| {
                            log::debug!("Including automata file {:?}", e.path());
                        })
                        .map(|f: &include_dir::File| f.contents_utf8().unwrap().to_string())
                        .collect()
                },
                // #[cfg(not(debug_assertions))]
                // {
                //     vec![
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cupid/automata/dce_rpc,gssapi,krb,ntlm-SF.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cupid/automata/dce_rpc,gssapi,krb-SF.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cupid/automata/dce_rpc,gssapi,krb,smb-RST.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cupid/automata/dce_rpc,gssapi,smb-RST.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cupid/automata/dce_rpc,ntlm-SF.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cupid/automata/dce_rpc-SF.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cupid/automata/dhcp.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cupid/automata/dns.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cupid/automata/gssapi,krb,smb-RST.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cupid/automata/gssapi,krb,smb-SF.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cupid/automata/gssapi,ntlm,smb-RST.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cupid/automata/gssapi,ntlm,smb-SF.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cupid/automata/gssapi,smb-RST.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cupid/automata/gssapi,smb-SF.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cupid/automata/http-RST.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cupid/automata/http-SF.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cupid/automata/krb.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cupid/automata/krb_tcp-RST.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cupid/automata/ldap_tcp-RST.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cupid/automata/ldap_udp.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cupid/automata/ntp.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cupid/automata/smtp-SF.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cupid/automata/ssl-RST.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/cupid/automata/ssl-SF.json",
                //             1
                //         ))
                //         .unwrap(),
                //     ]
                // },
            ),
            #[cfg(feature = "models_dedale")]
            ModelsSource::DEDALE => Ok(
                // #[cfg(debug_assertions)]
                {
                    let d: Dir =
                        include_dir!("$CARGO_MANIFEST_DIR/default_models/dedale/automata/");
                    d.find("**/*.json")
                        .unwrap()
                        .filter_map(|e: &DirEntry| e.as_file())
                        .filter(|e| !e.path().to_str().unwrap().ends_with("-language.json"))
                        .inspect(|e| {
                            log::debug!("Including automata file {:?}", e.path());
                        })
                        .map(|f: &include_dir::File| f.contents_utf8().unwrap().to_string())
                        .collect()
                },
                // #[cfg(not(debug_assertions))]
                // {
                //     vec![
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/dedale/automata/dce_rpc,gssapi,krb-RST.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/dedale/automata/dce_rpc,gssapi,krb-SF.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/dedale/automata/dce_rpc-RST.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/dedale/automata/dce_rpc-SF.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/dedale/automata/dhcp.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/dedale/automata/dns.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/dedale/automata/dns-SF.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/dedale/automata/gssapi,krb,smb-RST.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/dedale/automata/http-RST.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/dedale/automata/http-S0.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/dedale/automata/http-SF.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/dedale/automata/ldap_tcp-SF.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/dedale/automata/ldap_udp.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/dedale/automata/ntp.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/dedale/automata/quic,ssl.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/dedale/automata/smtp,ssl-SF.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/dedale/automata/ssl-RST.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/dedale/automata/ssl-S0.json",
                //             1
                //         ))
                //         .unwrap(),
                //         String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                //             "default_models/dedale/automata/ssl-SF.json",
                //             1
                //         ))
                //         .unwrap(),
                //     ]
                // },
            ),
            ModelsSource::UserDefined(path) => {
                let paths = fs::read_dir(Path::new(path).join("automata").to_str().unwrap())?;
                let mut automata = vec![];
                for p in paths {
                    let p = p.expect("Cannot open path").path();
                    if !p.is_dir() && p.extension() == Some(OsStr::new("json")) {
                        let string = fs::read_to_string(p)?;
                        automata.push(string);
                    }
                }
                Ok(automata)
            }
        }
    }

    pub(crate) fn get_bn(&self) -> std::io::Result<String> {
        match &self {
            #[cfg(feature = "models_cicids17")]
            ModelsSource::CICIDS17 => Ok(
                #[cfg(debug_assertions)]
                include_str!("../default_models/cicids17/bn/bn.bifxml").to_string(),
                #[cfg(not(debug_assertions))]
                {
                    String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                        "default_models/cicids17/bn/bn.bifxml",
                        1
                    ))
                    .unwrap()
                },
            ),

            #[cfg(feature = "models_cupid")]
            ModelsSource::CUPID => Ok(
                #[cfg(debug_assertions)]
                include_str!("../default_models/cupid/bn/bn.bifxml").to_string(),
                #[cfg(not(debug_assertions))]
                {
                    String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                        "default_models/cupid/bn/bn.bifxml",
                        1
                    ))
                    .unwrap()
                },
            ),

            #[cfg(feature = "models_dedale")]
            ModelsSource::DEDALE => Ok(
                #[cfg(debug_assertions)]
                include_str!("../default_models/dedale/bn/bn.bifxml").to_string(),
                #[cfg(not(debug_assertions))]
                {
                    String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                        "default_models/dedale/bn/bn.bifxml",
                        1
                    ))
                    .unwrap()
                },
            ),

            ModelsSource::UserDefined(path) => {
                let p = Path::new(path);
                Ok(fs::read_to_string(
                    p.join("bn/bn.bifxml").to_str().unwrap(),
                )?)
            }
        }
    }

    pub(crate) fn get_pkt_count_clusters(&self) -> Result<String, String> {
        match &self {
            #[cfg(feature = "models_cicids17")]
            ModelsSource::CICIDS17 => Ok(
                #[cfg(debug_assertions)]
                include_str!("../default_models/cicids17/pkt_count_clusters.json").to_string(),
                #[cfg(not(debug_assertions))]
                {
                    String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                        "default_models/cicids17/pkt_count_clusters.json",
                        1
                    ))
                    .unwrap()
                },
            ),

            #[cfg(feature = "models_cupid")]
            ModelsSource::CUPID => Ok(
                #[cfg(debug_assertions)]
                include_str!("../default_models/cupid/pkt_count_clusters.json").to_string(),
                #[cfg(not(debug_assertions))]
                {
                    String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                        "default_models/cupid/pkt_count_clusters.json",
                        1
                    ))
                    .unwrap()
                },
            ),

            #[cfg(feature = "models_dedale")]
            ModelsSource::DEDALE => Ok(
                #[cfg(debug_assertions)]
                include_str!("../default_models/dedale/pkt_count_clusters.json").to_string(),
                #[cfg(not(debug_assertions))]
                {
                    String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                        "default_models/dedale/pkt_count_clusters.json",
                        1
                    ))
                    .unwrap()
                },
            ),

            ModelsSource::UserDefined(path) => Ok(fs::read_to_string(
                Path::new(path)
                    .join("pkt_count_clusters.json")
                    .to_str()
                    .unwrap(),
            )
            .map_err(|e| format!("Cannot open the packet count clusters file: {e}"))?),
        }
    }

    pub(crate) fn get_time_profile(&self) -> Result<String, String> {
        match &self {
            #[cfg(feature = "models_cicids17")]
            ModelsSource::CICIDS17 => Ok(
                #[cfg(debug_assertions)]
                include_str!("../default_models/cicids17/time_profile.json").to_string(),
                #[cfg(not(debug_assertions))]
                {
                    String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                        "default_models/cicids17/time_profile.json",
                        1
                    ))
                    .unwrap()
                },
            ),
            #[cfg(feature = "models_cupid")]
            ModelsSource::CUPID => Ok(
                #[cfg(debug_assertions)]
                include_str!("../default_models/cupid/time_profile.json").to_string(),
                #[cfg(not(debug_assertions))]
                {
                    String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                        "default_models/cupid/time_profile.json",
                        1
                    ))
                    .unwrap()
                },
            ),
            #[cfg(feature = "models_dedale")]
            ModelsSource::DEDALE => Ok(
                #[cfg(debug_assertions)]
                include_str!("../default_models/dedale/time_profile.json").to_string(),
                #[cfg(not(debug_assertions))]
                {
                    String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                        "default_models/dedale/time_profile.json",
                        1
                    ))
                    .unwrap()
                },
            ),

            ModelsSource::UserDefined(path) => Ok(fs::read_to_string(
                Path::new(path).join("time_profile.json").to_str().unwrap(),
            )
            .map_err(|e| format!("Cannot open the time profile file: {e}"))?),
        }
    }
}
