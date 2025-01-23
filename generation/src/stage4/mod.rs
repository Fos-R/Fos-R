#![allow(unused)]

use crate::*;

pub struct Stage4 {
    interface: Ipv4Addr,
    proto: u8,
    // TODO: add raw socket
}

impl Stage4 {
    pub fn new(interface: Ipv4Addr, proto: u8) -> Self {
        Stage4 { interface, proto }
    }

    pub fn send(&self, packets: SeededData<Packets>) {
        // send packets related to one flow
        // flow contains the metadata to configure the socket
        // before sending the next packet, we need to wait for the answer
        // we should reemit packet after a timeout in case we do not receive the answer
        // the part must be cross-platform and use raw socket
        todo!()
    }
}
