#![allow(unused)]

use crate::structs::*;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct UDPPacketInfo {
    pub payload: Payload,
    pub ts: Duration,
    pub direction: PacketDirection,
    pub noise: NoiseType,
}

impl PacketInfo for UDPPacketInfo {
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
pub struct UDPEdgeTuple {
    pub payload_type: PayloadType,
    pub direction: PacketDirection,
}

impl EdgeType for UDPEdgeTuple {
    fn get_payload_type(&self) -> &PayloadType {
        &self.payload_type
    }
    fn get_direction(&self) -> PacketDirection {
        self.direction
    }
}

pub fn parse_udp_symbol(symbol: String, p: PayloadType) -> UDPEdgeTuple {
    let strings: Vec<&str> = symbol.split("_").collect();
    UDPEdgeTuple {
        direction: match strings[0] {
            ">" => PacketDirection::Forward,
            _ => PacketDirection::Backward,
        },
        payload_type: p,
    }
}

pub fn create_udp_header(
    payload: Payload,
    noise: NoiseType,
    ts: Duration,
    e: &UDPEdgeTuple,
) -> UDPPacketInfo {
    UDPPacketInfo {
        payload,
        noise,
        ts,
        direction: e.direction,
    }
}
