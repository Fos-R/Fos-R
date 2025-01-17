#![allow(unused)]

use crate::structs::*;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ICMPPacketInfo {
    // we assume no payload
    // we may need to add more fields to correctly generate them
    pub ts: Duration,
    pub direction: PacketDirection,
    pub noise: NoiseType,
}

impl PacketInfo for ICMPPacketInfo {
    fn get_direction(&self) -> PacketDirection {
        self.direction
    }
    fn get_ts(&self) -> Duration {
        self.ts
    }
    fn get_noise_type(&self) -> NoiseType {
        self.noise
    }
}

#[derive(Debug, Clone)]
pub struct ICMPEdgeTuple {
    pub direction: PacketDirection,
}

impl EdgeType for ICMPEdgeTuple {
    fn get_payload_type(&self) -> &PayloadType {
        &PayloadType::Empty
    }
}

pub fn parse_icmp_symbol(symbol: String, _t: PayloadType) -> ICMPEdgeTuple {
    ICMPEdgeTuple {
        direction: match symbol.as_str() {
            ">" => PacketDirection::Forward,
            _ => PacketDirection::Backward,
        },
    }
}

pub fn create_icmp_header(
    _payload: Payload,
    noise: NoiseType,
    ts: Duration,
    e: &ICMPEdgeTuple,
) -> ICMPPacketInfo {
    ICMPPacketInfo {
        ts,
        direction: e.direction,
        noise,
    }
}
