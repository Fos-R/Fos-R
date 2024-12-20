#![allow(unused)]

use crate::*;

pub struct Stage4 {
    interface: String,
}

impl Stage4 {

    pub fn new(interface: &String) -> Self {
        Stage4 { interface: interface.clone() }
    }

    pub fn send(&self, flow: &Flow, input: &Vec<Packet>) {
        // flow contains the metadata to configure the socket
        panic!("Not implemented");
    }

}
