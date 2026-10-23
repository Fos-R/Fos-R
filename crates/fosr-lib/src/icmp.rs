use crate::structs::{EdgeType, PacketDirection, PacketInfo, Payload, PayloadType};
use std::time::Duration;

#[derive(Debug, Clone)]
/// Some information about an Icmp packet
pub struct IcmpPacketInfo {
    // we assume no payload
    // we may need to add more fields to correctly generate them
    /// the timestamp of the packet
    pub ts: Duration,
    /// the direction of the packet
    pub direction: PacketDirection,
}

impl PacketInfo for IcmpPacketInfo {
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
pub struct IcmpEdgeTuple {
    pub direction: PacketDirection,
}

impl EdgeType for IcmpEdgeTuple {
    fn get_payload_type(&self) -> &PayloadType {
        &PayloadType::Empty
    }
    fn get_direction(&self) -> PacketDirection {
        self.direction
    }
}

#[allow(unused)]
pub fn parse_icmp_symbol(symbol: &str, _t: PayloadType) -> IcmpEdgeTuple {
    IcmpEdgeTuple {
        direction: match symbol {
            ">" => PacketDirection::Forward,
            _ => PacketDirection::Backward,
        },
    }
}

#[allow(unused)]
pub fn create_icmp_header(_payload: Payload, ts: Duration, e: &IcmpEdgeTuple) -> IcmpPacketInfo {
    IcmpPacketInfo {
        ts,
        direction: e.direction,
    }
}
