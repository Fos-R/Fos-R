#![allow(unused)]

use crate::structs::*;
use std::time::Instant;

#[derive(Debug,Clone)]
pub struct UDPPacketInfo {
    pub payload: Payload,
    pub ts: Instant,
    pub direction: PacketDirection
}

impl Protocol for UDPPacketInfo {
    fn get_direction(&self) -> PacketDirection {
        self.direction
    }
    fn get_ts(&self) -> Instant {
        self.ts
    }
}

#[derive(Debug,Clone)]
pub struct UDPEdgeTuple {
    pub payload_type: PayloadType,
    pub direction: PacketDirection
}

impl EdgeType for UDPEdgeTuple {
    fn get_payload_type(&self) -> &PayloadType {
        &self.payload_type
    }
}

pub fn parse_udp_symbol(symbol: String, tss: JsonPayload) -> UDPEdgeTuple {
    let strings : Vec<&str> = symbol.split("_").collect();
    UDPEdgeTuple {  direction:
        match strings[0] {
            _ if strings[0] == ">" => PacketDirection::Forward,
            _ => PacketDirection::Backward
        },
                    payload_type:
                        match tss {
                            JsonPayload::Lengths { lengths: l } => PayloadType::Random(l),
                            JsonPayload::NoPayload => PayloadType::Empty,
                            JsonPayload::HexCodes { payloads: p } => PayloadType::Replay(p.into_iter().map(|s| hex::decode(s).expect("Payload decoding failed")).collect())
        },
    }
}

pub fn create_udp_header(payload: Payload, ts: Instant, e: &UDPEdgeTuple) -> UDPPacketInfo {
    UDPPacketInfo { payload, ts, direction: e.direction }
}
