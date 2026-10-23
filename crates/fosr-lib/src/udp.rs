use crate::structs::{EdgeType, PacketDirection, PacketInfo, Payload, PayloadType};
use std::time::Duration;

#[derive(Debug, Clone)]
/// Some information about a UDP packet
pub struct UdpPacketInfo {
    /// the payload of the packet
    pub payload: Payload,
    /// the timestamp of the packet
    pub ts: Duration,
    /// the direction of the packet
    pub direction: PacketDirection,
}

impl PacketInfo for UdpPacketInfo {
    fn get_direction(&self) -> PacketDirection {
        self.direction
    }
    fn get_ts(&self) -> Duration {
        self.ts
    }
    fn set_ts(&mut self, ts: Duration) {
        self.ts = ts;
    }
}

#[derive(Debug, Clone)]
pub struct UdpEdgeTuple {
    pub payload_type: PayloadType,
    pub direction: PacketDirection,
}

impl EdgeType for UdpEdgeTuple {
    fn get_payload_type(&self) -> &PayloadType {
        &self.payload_type
    }
    fn get_direction(&self) -> PacketDirection {
        self.direction
    }
}

pub fn parse_udp_symbol(symbol: &str, p: PayloadType) -> UdpEdgeTuple {
    let strings: Vec<&str> = symbol.split('_').collect();
    UdpEdgeTuple {
        direction: match strings[0] {
            ">" => PacketDirection::Forward,
            _ => PacketDirection::Backward,
        },
        payload_type: p,
    }
}

#[allow(unused)]
pub fn create_udp_header(payload: Payload, ts: Duration, e: &UdpEdgeTuple) -> UdpPacketInfo {
    UdpPacketInfo {
        payload,
        ts,
        direction: e.direction,
    }
}
