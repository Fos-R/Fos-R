#![allow(unused)]

use crate::*;

pub struct Stage4 {
    interfaces: Vec<String>,
}

impl Stage4 {

    pub fn new(proto: u8) -> Self {
        // TODO: probe the available interfaces
        Stage4 { interfaces: vec![] }
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
