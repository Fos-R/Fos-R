use crate::stage2::*;

pub struct ReplayGenerator;

#[allow(unused)]
impl Stage2 for ReplayGenerator {

    fn generate_tcp_packets_info(&self, mut flow: SeededData<FlowData>) -> SeededData<PacketsIR<TCPPacketInfo>> {
        todo!()
    }

    fn generate_udp_packets_info(&self, flow: SeededData<FlowData>) -> SeededData<PacketsIR<UDPPacketInfo>> {
        todo!()
    }

    fn generate_icmp_packets_info(&self, flow: SeededData<FlowData>) -> SeededData<PacketsIR<ICMPPacketInfo>> {
        todo!()
    }

}

