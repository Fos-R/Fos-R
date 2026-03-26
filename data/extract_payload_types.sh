#!/bin/sh

# This extraction is required for learning the automata
FLAGS="-e http.request.method -e http.response.code -e dhcp.type -e kerberos.msg_type -e dns.flags -e ntp.flags -e smtp.req.command -e smtp.response.code -e tls.record.content_type -e tls.record.opaque_type -e tls.handshake.type -e dcerpc.pkt_type -e dcerpc.cn_flags -e ftp.request.command -e ftp.response.code -e ldap.protocolOp -e ssh.message_code -e telnet.cmd -e tftp.opcode -e pop.request.command -e pop.response.indicator -e rtp.p_type -e imap.request.command -e imap.response.status -e bgp.type -e sip.Method -e sip.Status-Code -e rdp.neg_type -e nbss.type -e smb.cmd -e drsuapi.opnum -e radius.code -e snmp.msgFlags"
echo "Extraction TCP payload types"
tshark -r data.pcap -T fields -E header=y -E separator=, -E occurrence=f -e tcp.payload $FLAGS "tcp.len > 0" | sed 's/\([0-f]\{50\}\)[0-f]*,/\1,/' > payload_tcp.csv
echo "Extraction UDP payload types"
tshark -r data.pcap -T fields -E header=y -E separator=, -E occurrence=f -e udp.payload $FLAGS "udp.length > 0" | sed 's/\([0-f]\{50\}\)[0-f]*,/\1,/' > payload_udp.csv
