use crate::config;
use crate::{stage1, stage2, stage3};
use std::ffi::OsStr;
use std::fs;
use std::path::Path;

/// The source of models
pub enum ModelsSource {
    #[cfg(feature = "models_cicids17")]
    /// Models based on the first day of CICIDS2017 dataset
    CICIDS17,
    #[cfg(feature = "models_cupid")]
    /// Models based on the first day of CICIDS2017 dataset
    CUPID,
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

    pub fn with_config(mut self, path: &str) -> Result<Self, String> {
        let config = config::import_config(
            &fs::read_to_string(Path::new(path))
                .map_err(|e| format!("Cannot open the configuration file: {e}"))?,
        );
        self.bn.apply_config(&config)?;
        Ok(self)
    }

    pub fn with_string_config(mut self, config: &str) -> Result<Self, String> {
        let config = config::import_config(config);
        self.bn.apply_config(&config)?;
        Ok(self)
    }
}

impl ModelsSource {
    pub(crate) fn get_automata(&self) -> std::io::Result<Vec<String>> {
        match &self {
            #[cfg(feature = "models_cicids17")]
            ModelsSource::CICIDS17 => Ok(
                #[cfg(debug_assertions)]
                {
                    vec![
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/dns-SF.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/dns.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/ftp-data-SF.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/ftp-SF.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/http-REJ.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/http-RST.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/http-S0.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/http-SF.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/http-SH.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/krb.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/ldap_tcp-REJ.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/ldap_tcp-RST.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/ntp.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/ssh-S0.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/ssh-SF.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/ssl-REJ.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/ssl-RST.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/ssl-S0.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/ssl-SF.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/ssl-SH.json",
                            1
                        ))
                        .unwrap(),
                    ]
                },
                #[cfg(not(debug_assertions))]
                {
                    vec![
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/dns-SF.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/dns.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/ftp-data-SF.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/ftp-SF.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/http-REJ.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/http-RST.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/http-S0.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/http-SF.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/http-SH.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/krb.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/ldap_tcp-REJ.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/ldap_tcp-RST.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/ntp.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/ssh-S0.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/ssh-SF.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/ssl-REJ.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/ssl-RST.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/ssl-S0.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/ssl-SF.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/automata/ssl-SH.json",
                            22
                        ))
                        .unwrap(),
                    ]
                },
            ),
            #[cfg(feature = "models_cupid")]
            ModelsSource::CUPID => Ok(
                #[cfg(debug_assertions)]
                {
                    vec![
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/dce_rpc-SF.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/dns.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/gssapi,dce_rpc,ntlm-SF.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/gssapi,dce_rpc-SF.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/gssapi,ntlm,smb-RST.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/gssapi,ntlm,smb-SF.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/gssapi,smb,dce_rpc-RST.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/gssapi,smb,krb-RST.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/gssapi,smb,krb-SF.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/gssapi,smb,ntlm-RST.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/gssapi,smb,ntlm-SF.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/gssapi,smb-RST.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/gssapi,smb-SF.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/http-RST.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/http-S0.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/http-SF.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/krb.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/krb_tcp-RST.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/krb_tcp-SH.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/ldap_tcp-REJ.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/ldap_tcp-RST.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/ldap_udp.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/ntlm,dce_rpc-SF.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/ntp.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/smtp-SF.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/ssl-RST.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/ssl-S0.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/ssl-SF.json",
                            1
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/ssl-SH.json",
                            1
                        ))
                        .unwrap(),
                    ]
                },
                #[cfg(not(debug_assertions))]
                {
                    vec![
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/dce_rpc-SF.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/dns.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/gssapi,dce_rpc,ntlm-SF.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/gssapi,dce_rpc-SF.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/gssapi,ntlm,smb-RST.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/gssapi,ntlm,smb-SF.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/gssapi,smb,dce_rpc-RST.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/gssapi,smb,krb-RST.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/gssapi,smb,krb-SF.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/gssapi,smb,ntlm-RST.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/gssapi,smb,ntlm-SF.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/gssapi,smb-RST.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/gssapi,smb-SF.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/http-RST.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/http-S0.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/http-SF.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/krb.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/krb_tcp-RST.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/krb_tcp-SH.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/ldap_tcp-REJ.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/ldap_tcp-RST.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/ldap_udp.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/ntlm,dce_rpc-SF.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/ntp.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/smtp-SF.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/ssl-RST.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/ssl-S0.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/ssl-SF.json",
                            22
                        ))
                        .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/automata/ssl-SH.json",
                            22
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
                        let string = fs::read_to_string(p)?;
                        automata.push(string);
                    }
                }
                Ok(automata)
            }
        }
    }

    pub(crate) fn get_bn(&self) -> std::io::Result<Vec<String>> {
        match &self {
            #[cfg(feature = "models_cicids17")]
            ModelsSource::CICIDS17 => Ok(
                #[cfg(debug_assertions)]
                {
                    vec![
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/bn/bn_common.bifxml",
                            1
                        ))
                        .unwrap(),
                        String::new(),
                        String::new(),
                        // String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                        //     "default_models/cicids17/bn/bn_tcp.bifxml",
                        //     1
                        // ))
                        // .unwrap(),
                        // String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                        //     "default_models/cicids17/bn/bn_udp.bifxml",
                        //     1
                        // ))
                        // .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/bn/bn_additional_data.json",
                            1
                        ))
                        .unwrap(),
                    ]
                },
                #[cfg(not(debug_assertions))]
                {
                    vec![
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/bn/bn_common.bifxml",
                            22
                        ))
                        .unwrap(),
                        String::new(),
                        String::new(),
                        // String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                        //     "default_models/cicids17/bn/bn_tcp.bifxml",
                        //     22
                        // ))
                        // .unwrap(),
                        // String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                        //     "default_models/cicids17/bn/bn_udp.bifxml",
                        //     22
                        // ))
                        // .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cicids17/bn/bn_additional_data.json",
                            22
                        ))
                        .unwrap(),
                    ]
                },
            ),
            #[cfg(feature = "models_cupid")]
            ModelsSource::CUPID => Ok(
                #[cfg(debug_assertions)]
                {
                    vec![
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/bn/bn_common.bifxml",
                            1
                        ))
                        .unwrap(),
                        String::new(),
                        String::new(),
                        // String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                        //     "default_models/cupid/bn/bn_tcp.bifxml",
                        //     1
                        // ))
                        // .unwrap(),
                        // String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                        //     "default_models/cupid/bn/bn_udp.bifxml",
                        //     1
                        // ))
                        // .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/bn/bn_additional_data.json",
                            1
                        ))
                        .unwrap(),
                    ]
                },
                #[cfg(not(debug_assertions))]
                {
                    vec![
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/bn/bn_common.bifxml",
                            22
                        ))
                        .unwrap(),
                        String::new(),
                        String::new(),
                        // String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                        //     "default_models/cupid/bn/bn_tcp.bifxml",
                        //     22
                        // ))
                        // .unwrap(),
                        // String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                        //     "default_models/cupid/bn/bn_udp.bifxml",
                        //     22
                        // ))
                        // .unwrap(),
                        String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                            "default_models/cupid/bn/bn_additional_data.json",
                            22
                        ))
                        .unwrap(),
                    ]
                },
            ),

            ModelsSource::UserDefined(path) => {
                let p = Path::new(path);
                Ok(vec![
                    fs::read_to_string(p.join("bn/bn_common.bifxml").to_str().unwrap())?,
                    String::new(),
                    String::new(),
                    // fs::read_to_string(p.join("bn/bn_tcp.bifxml").to_str().unwrap())?,
                    // fs::read_to_string(p.join("bn/bn_udp.bifxml").to_str().unwrap())?,
                    fs::read_to_string(p.join("bn/bn_additional_data.json").to_str().unwrap())?,
                ])
            }
        }
    }

    pub(crate) fn get_time_profile(&self) -> Result<String, String> {
        match &self {
            #[cfg(feature = "models_cicids17")]
            ModelsSource::CICIDS17 => Ok(
                #[cfg(debug_assertions)]
                {
                    String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                        "default_models/cicids17/time_profile.json",
                        1
                    ))
                    .unwrap()
                },
                #[cfg(not(debug_assertions))]
                {
                    String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                        "default_models/cicids17/time_profile.json",
                        22
                    ))
                    .unwrap()
                },
            ),
            #[cfg(feature = "models_cupid")]
            ModelsSource::CUPID => Ok(
                #[cfg(debug_assertions)]
                {
                    String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                        "default_models/cupid/time_profile.json",
                        1
                    ))
                    .unwrap()
                },
                #[cfg(not(debug_assertions))]
                {
                    String::from_utf8(include_bytes_zstd::include_bytes_zstd!(
                        "default_models/cupid/time_profile.json",
                        22
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
