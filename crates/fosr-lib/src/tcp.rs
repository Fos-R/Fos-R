use crate::structs::*;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct TCPPacketInfo {
    /// the payload of the packet
    pub payload: Payload,
    /// the timestamp of the packet
    pub ts: Duration,
    /// the direction of the packet
    pub direction: PacketDirection,
    /// whether the packet is a noise
    pub noise: NoiseType,
    /// SYN flag?
    pub s_flag: bool,
    /// ACK flag?
    pub a_flag: bool,
    /// FIN flag?
    pub f_flag: bool,
    /// RST flag?
    pub r_flag: bool,
    /// URG flag?
    pub u_flag: bool,
    /// PSH flag?
    pub p_flag: bool,
}

impl PacketInfo for TCPPacketInfo {
    fn get_direction(&self) -> PacketDirection {
        self.direction
    }
    fn get_ts(&self) -> Duration {
        self.ts
    }
    fn get_noise_type(&self) -> NoiseType {
        self.noise
    }
    fn set_ts(&mut self, ts: Duration) {
        self.ts = ts
    }
}

#[derive(Debug, Clone)]
pub struct TCPEdgeTuple {
    pub payload_type: PayloadType,
    pub direction: PacketDirection,
    pub s_flag: bool,
    pub a_flag: bool,
    pub f_flag: bool,
    pub r_flag: bool,
    pub u_flag: bool,
    pub p_flag: bool,
}

impl EdgeType for TCPEdgeTuple {
    fn get_payload_type(&self) -> &PayloadType {
        &self.payload_type
    }
    fn get_direction(&self) -> PacketDirection {
        self.direction
    }
}

pub fn parse_tcp_symbol(symbol: String, p: PayloadType) -> TCPEdgeTuple {
    let strings: Vec<&str> = symbol.split("_").collect();
    TCPEdgeTuple {
        direction: match strings[1] {
            ">" => PacketDirection::Forward,
            _ => PacketDirection::Backward,
        },
        payload_type: p,
        s_flag: strings[0].find('S').is_some(),
        a_flag: strings[0].find('A').is_some(),
        f_flag: strings[0].find('F').is_some(),
        r_flag: strings[0].find('R').is_some(),
        u_flag: strings[0].find('U').is_some(),
        p_flag: strings[0].find('P').is_some(),
    }
}

pub fn create_tcp_header(
    payload: Payload,
    noise: NoiseType,
    ts: Duration,
    e: &TCPEdgeTuple,
) -> TCPPacketInfo {
    TCPPacketInfo {
        payload,
        ts,
        noise,
        direction: e.direction,
        s_flag: e.s_flag,
        a_flag: e.a_flag,
        f_flag: e.f_flag,
        r_flag: e.r_flag,
        u_flag: e.u_flag,
        p_flag: e.p_flag,
    }
}
