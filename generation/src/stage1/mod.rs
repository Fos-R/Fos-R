#![allow(unused)]

use crate::structs::*;
use std::time::Duration;

pub mod flowchronicle;

pub trait Stage1 {
    fn generate_flows(&self, ts: SeededData<Duration>) -> Vec<SeededData<Flow>>;
}
