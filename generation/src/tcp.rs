#![allow(unused)]

use crate::structs::*;
use std::time::Instant;

#[derive(Debug,Clone)]
pub struct TCPPacketInfo {
    pub payload: Payload,
    pub ts: Instant,
    pub direction: PacketDirection,
    pub s_flag: bool,
    pub a_flag: bool,
    pub f_flag: bool,
    pub r_flag: bool,
    pub u_flag: bool,
    pub p_flag: bool
}

impl Protocol for TCPPacketInfo {
    fn get_direction(&self) -> PacketDirection {
        self.direction
    }
    fn get_ts(&self) -> Instant {
        self.ts
    }
}

#[derive(Debug,Clone)]
pub struct TCPEdgeTuple {
    pub payload_type: PayloadType,
    pub direction: PacketDirection,
    pub s_flag: bool,
    pub a_flag: bool,
    pub f_flag: bool,
    pub r_flag: bool,
    pub u_flag: bool,
    pub p_flag: bool
}

impl EdgeType for TCPEdgeTuple {
    fn get_payload_type(&self) -> &PayloadType {
        &self.payload_type
    }
}

pub fn parse_tcp_symbol(symbol: String, tss: JsonPayload) -> TCPEdgeTuple {
    let strings : Vec<&str> = symbol.split("_").collect();
    TCPEdgeTuple {  direction:
        match strings[1] {
            _ if strings[1] == ">" => PacketDirection::Forward,
            _ => PacketDirection::Backward
        },
                    payload_type:
                        match tss {
                            JsonPayload::Lengths { lengths: l } => PayloadType::Random(l),
                            JsonPayload::NoPayload => PayloadType::Empty,
                            JsonPayload::HexCodes { payloads: p } => PayloadType::Replay(p.into_iter().map(|s| hex::decode(s).expect("Payload decoding failed")).collect())
        },
                    s_flag: strings[0].find('S').is_some(),
                    a_flag: strings[0].find('A').is_some(),
                    f_flag: strings[0].find('F').is_some(),
                    r_flag: strings[0].find('R').is_some(),
                    u_flag: strings[0].find('U').is_some(),
                    p_flag: strings[0].find('P').is_some(),
    }

}

pub fn create_tcp_header(payload: Payload, ts: Instant, e: &TCPEdgeTuple) -> TCPPacketInfo {
    TCPPacketInfo {
        payload,
        ts,
        direction: e.direction,
        s_flag: e.s_flag,
        a_flag: e.a_flag,
        f_flag: e.f_flag,
        r_flag: e.r_flag,
        u_flag: e.u_flag,
        p_flag: e.p_flag
    }
}
