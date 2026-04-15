use crate::structs::*;
use std::time::Duration;

#[derive(Debug, Clone)]
/// Some information about a UDP packet
pub struct UDPPacketInfo {
    /// the payload of the packet
    pub payload: Payload,
    /// the timestamp of the packet
    pub ts: Duration,
    /// the direction of the packet
    pub direction: PacketDirection,
}

impl PacketInfo for UDPPacketInfo {
    fn get_direction(&self) -> PacketDirection {
        self.direction
    }
    fn get_ts(&self) -> Duration {
        self.ts
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

#[allow(unused)]
pub fn create_udp_header(payload: Payload, ts: Duration, e: &UDPEdgeTuple) -> UDPPacketInfo {
    UDPPacketInfo {
        payload,
        ts,
        direction: e.direction,
    }
}
