#!/bin/sh
# This script is used to extract feature prior to Fos-R model training

if [ -f "data.pcap" ]; then
    echo "Zeek analysis"
    zeek -C -r data.pcap ../../fosr_feature_extraction.zeek
    FLAGS="-e http.request.method -e http.response.code -e dhcp.type -e kerberos.msg_type -e dns.flags -e ntp.flags -e smtp.req.command -e smtp.response.code -e tls.record.content_type -e tls.record.opaque_type -e tls.handshake.type -e dcerpc.pkt_type -e dcerpc.cn_flags -e ftp.request.command -e ftp.response.code -e ldap.protocolOp -e ssh.message_code -e telnet.cmd -e tftp.opcode -e pop.request.command -e pop.response.indicator -e rtp.p_type -e imap.request.command -e imap.response.status -e bgp.type -e sip.Method -e sip.Status-Code -e rdp.neg_type -e nbss.type -e smb.cmd -e drsuapi.opnum -e radius.code -e snmp.msgFlags -e quic.frame_type"
    echo "TCP payload types extraction"
    # Adding -2 to tshark brings nothing because Zeek is one pass only
    # the sed commands do two operations:
    # - ignore packets with no fields set
    # - keep only the beginning of the payload
    tshark -r data.pcap -T fields -E header=y -E separator=, -E aggregator=\& -e tcp.payload $FLAGS "tcp.len > 0" | sed '/^[0-f]*,*$/d' | sed 's/\([0-f]\{50\}\)[0-f]*,/\1,/' > payload_tcp.csv
    echo "UDP payload types extraction"
    tshark -r data.pcap -T fields -E header=y -E separator=, -E aggregator=\& -e udp.payload $FLAGS "udp.length > 0" | sed '/^[0-f]*,*$/d' | sed 's/\([0-f]\{50\}\)[0-f]*,/\1,/' > payload_udp.csv
else
    echo "Call this script from a directory containing data.pcap"
fi
