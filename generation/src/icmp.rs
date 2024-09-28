#![allow(unused)]

use crate::structs::*;
use std::time::Instant;

#[derive(Debug,Clone)]
pub struct ICMPPacketInfo {
    // we assume no payload
    // we may need to add more fields to correctly generate them
    pub ts: Instant,
    pub direction: PacketDirection
}

impl Protocol for ICMPPacketInfo {
    fn get_direction(&self) -> PacketDirection {
        self.direction
    }
    fn get_ts(&self) -> Instant {
        self.ts
    }
}

#[derive(Debug,Clone)]
pub struct ICMPEdgeTuple {
    pub direction: PacketDirection
}

impl EdgeType for ICMPEdgeTuple {
    fn get_payload_type(&self) -> &PayloadType {
        &PayloadType::Empty
    }
}

pub fn parse_icmp_symbol(symbol: String, tss: JsonPayload) -> ICMPEdgeTuple {
    if let JsonPayload::NoPayload = tss {
        ICMPEdgeTuple { direction:
            match symbol {
                _ if symbol == ">" => PacketDirection::Forward,
                _ => PacketDirection::Backward
            }
        }
    } else {
        panic!("ICMP packet with payload?")
    }
}

pub fn create_icmp_header(_payload: Payload, ts: Instant, e: &ICMPEdgeTuple) -> ICMPPacketInfo {
    ICMPPacketInfo { ts, direction: e.direction }
}
