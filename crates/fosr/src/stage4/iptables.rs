use crate::stage4::*;

#[derive(Debug, Clone)]
pub struct IPTablesStage4 {
    // Params
    taint: bool,
    fast: bool,
}

impl Stage4 for IPTablesStage4 {
    fn is_fast(&self) -> bool {
        self.fast
    }

    fn is_packet_relevant(&self, flags: u8) -> bool {
        !self.taint || flags & 0b100 > 0 // we know the traffic is tainted
    }

    /// Closes the current session via iptables rules in Linux.
    /// This function removes firewall rules created for the session.
    fn close_session(&self, f: &FlowId) {
        use std::process::Command;

        log::debug!("Ip tables removed for {f:?}");
        let status = Command::new("iptables")
            .args([
                "-w",
                "-t",
                "mangle",
                "-D",
                "OUTPUT",
                "-j",
                "DROP",
                "--match",
                "ttl",
                "--ttl-eq",
                "64",
                "-p",
                &format!("{:?}", f.protocol),
                "--sport",
                &format!("{}", f.src_port),
                "--dport",
                &format!("{}", f.dst_port),
                "-s",
                &format!("{}", f.src_ip),
                "-d",
                &format!("{}", f.dst_ip),
            ])
            .status()
            .expect("failed to execute process");
        assert!(status.success());

        let status = Command::new("iptables")
            .args([
                "-w",
                "-t",
                "mangle",
                "-D",
                "OUTPUT",
                "-j",
                "TTL",
                "--ttl-dec",
                "1",
                "-p",
                &format!("{:?}", f.protocol),
                "--sport",
                &format!("{}", f.src_port),
                "--dport",
                &format!("{}", f.dst_port),
                "-s",
                &format!("{}", f.src_ip),
                "-d",
                &format!("{}", f.dst_ip),
            ])
            .status()
            .expect("failed to execute process");
        assert!(status.success());
    }

    /// Opens a session by creating iptables rules on Linux.
    /// Establishes firewall rules to monitor and control outgoing packets for this session.
    fn open_session(&self, f: &FlowId) {
        // TODO: name chain "fosr"?
        // TODO: modifier la chaîne pour prendre en compte d’UDP

        use std::process::Command;

        log::debug!("Ip tables created for {}", f.src_port);
        let status = Command::new("iptables")
            .args([
                "-w",
                "-t",
                "mangle",
                "-A",
                "OUTPUT",
                "-j",
                "DROP",
                "--match",
                "ttl",
                "--ttl-eq",
                "64",
                "-p",
                &format!("{:?}", f.protocol),
                "--sport",
                &format!("{}", f.src_port),
                "--dport",
                &format!("{}", f.dst_port),
                "-s",
                &format!("{}", f.src_ip),
                "-d",
                &format!("{}", f.dst_ip),
            ])
            .status()
            .expect("failed to execute process");
        assert!(status.success());

        let status = Command::new("iptables")
            .args([
                "-w",
                "-t",
                "mangle",
                "-A",
                "OUTPUT",
                "-j",
                "TTL",
                "--ttl-dec",
                "1",
                "-p",
                &format!("{:?}", f.protocol),
                "--sport",
                &format!("{}", f.src_port),
                "--dport",
                &format!("{}", f.dst_port),
                "-s",
                &format!("{}", f.src_ip),
                "-d",
                &format!("{}", f.dst_ip),
            ])
            .status()
            .expect("failed to execute process");
        assert!(status.success());

        log::debug!("Ip tables created for {}", f.src_port);
    }
}

impl IPTablesStage4 {
    pub fn new(taint: bool, fast: bool) -> Self {
        IPTablesStage4 { taint, fast }
    }
}
