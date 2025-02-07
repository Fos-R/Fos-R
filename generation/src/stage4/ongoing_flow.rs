use std::cmp::Ordering;

use crate::{PacketDirection, Packets, SeededData};

pub(super) struct OngoingFlow {
    pub flow: SeededData<Packets>,
    pub direction: PacketDirection,
}

// Used to order packets by timestamp in a binary heap
impl Ord for OngoingFlow {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.flow.data.packets.is_empty() {
            return Ordering::Greater;
        } else if other.flow.data.packets.is_empty() {
            return Ordering::Less;
        }
        self.flow.data.packets[0].cmp(&other.flow.data.packets[0])
    }
}

impl PartialOrd for OngoingFlow {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for OngoingFlow {
    fn eq(&self, other: &Self) -> bool {
        self.flow.data.packets.is_empty() && other.flow.data.packets.is_empty()
            || self.flow.data.packets[0] == other.flow.data.packets[0]
    }
}

impl Eq for OngoingFlow {}
