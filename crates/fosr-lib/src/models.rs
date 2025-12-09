use crate::config;
use crate::{stage0, stage1, stage2};
use std::ffi::OsStr;
use std::fs;
use std::path::Path;

/// The source of models
pub enum ModelsSource {
    /// Models of Fos-R v0.1.2, only included for backward compatibility
    Legacy,
    // /// Models based on the first day of CICIDS2017 dataset
    // CICIDS17,
    /// Models defined by the user
    UserDefined(String),
}

/// The models
pub struct Models {
    /// The time model of stage 0
    pub time_bins: stage0::TimeModel,
    /// The Bayesian network of stage 1
    pub bn: stage1::bayesian_networks::BayesianModel,
    /// The automata of stage 2
    pub automata: stage2::tadam::AutomataLibrary,
}

impl Models {
    pub fn from_source(source: ModelsSource) -> Result<Self, String> {
        Ok(Models {
            automata: stage2::tadam::AutomataLibrary::from_source(&source)?,
            bn: stage1::bayesian_networks::BayesianModel::from_source(&source)?,
            time_bins: stage0::TimeModel::from_source(&source)?,
        })
    }

    pub fn with_config(mut self, path: &str) -> Result<Self, String> {
        let config = config::import_config(
            &fs::read_to_string(Path::new(path))
                .map_err(|_| "Cannot open the configuration file".to_string())?,
        );
        self.bn.apply_config(&config)?;
        Ok(self)
    }
}

impl ModelsSource {
    pub(crate) fn get_automata(&self) -> std::io::Result<Vec<String>> {
        match &self {
            ModelsSource::Legacy => Ok(
                #[cfg(debug_assertions)]
                {
                    vec![
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/legacy/automata/mqtt.json",
                            0
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/legacy/automata/smtp.json",
                            0
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/legacy/automata/ssh.json",
                            0
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/legacy/automata/https.json",
                            0
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/legacy/automata/dns.json",
                            0
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/legacy/automata/ntp.json",
                            0
                        ))
                        .unwrap(),
                    ]
                },
                #[cfg(not(debug_assertions))]
                {
                    vec![
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/legacy/automata/mqtt.json",
                            19
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/legacy/automata/smtp.json",
                            19
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/legacy/automata/ssh.json",
                            19
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/legacy/automata/https.json",
                            19
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/legacy/automata/dns.json",
                            19
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/legacy/automata/ntp.json",
                            19
                        ))
                        .unwrap(),
                    ]
                },
            ),
            ModelsSource::UserDefined(path) => {
                let paths = fs::read_dir(Path::new(path).join("automata").to_str().unwrap())?;
                let mut automata = vec![];
                for p in paths {
                    let p = p.expect("Cannot open path").path();
                    if !p.is_dir() && p.extension() == Some(OsStr::new("json")) {
                        let string = fs::read_to_string(p.file_name().unwrap())?;
                        automata.push(string);
                    }
                }
                Ok(automata)
            }
        }
    }

    pub(crate) fn get_bn(&self) -> std::io::Result<Vec<String>> {
        match &self {
            ModelsSource::Legacy => Ok(if cfg!(debug_assertions) {
                vec![
                    String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                        "default_models/legacy/bn/bn_common.bifxml",
                        0
                    ))
                    .unwrap(),
                    String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                        "default_models/legacy/bn/bn_tcp.bifxml",
                        0
                    ))
                    .unwrap(),
                    String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                        "default_models/legacy/bn/bn_udp.bifxml",
                        0
                    ))
                    .unwrap(),
                    String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                        "default_models/legacy/bn/bn_additional_data.json",
                        0
                    ))
                    .unwrap(),
                ]
            } else {
                vec![
                    String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                        "default_models/legacy/bn/bn_common.bifxml",
                        19
                    ))
                    .unwrap(),
                    String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                        "default_models/legacy/bn/bn_tcp.bifxml",
                        19
                    ))
                    .unwrap(),
                    String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                        "default_models/legacy/bn/bn_udp.bifxml",
                        19
                    ))
                    .unwrap(),
                    String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                        "default_models/legacy/bn/bn_additional_data.json",
                        19
                    ))
                    .unwrap(),
                ]
            }),
            ModelsSource::UserDefined(path) => {
                let p = Path::new(path);
                Ok(vec![
                    fs::read_to_string(p.join("bn/bn_common.bifxml").to_str().unwrap())?,
                    fs::read_to_string(p.join("bn/bn_tcp.bifxml").to_str().unwrap())?,
                    fs::read_to_string(p.join("bn/bn_udp.bifxml").to_str().unwrap())?,
                    fs::read_to_string(p.join("bn/bn_additional_data.json").to_str().unwrap())?,
                ])
            }
        }
    }

    pub(crate) fn get_time_profile(&self) -> Result<String, String> {
        match &self {
            ModelsSource::Legacy => Ok(String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                "default_models/legacy/time_profile.json",
                19
            ))
            .unwrap()),
            ModelsSource::UserDefined(path) => Ok(fs::read_to_string(
                Path::new(path).join("time_profile.json").to_str().unwrap(),
            )
            .map_err(|_| "Cannot open the time profile file".to_string())?),
        }
    }
}
