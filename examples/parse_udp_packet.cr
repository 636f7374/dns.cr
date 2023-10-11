require "../src/dns.cr"

buffer = uninitialized UInt8[4096_i32]
ask_packet = DNS::Packet.create_query_packet protocol_type: DNS::ProtocolType::UDP, name: "8.8.8.8.in-addr.arpa", record_type: DNS::Packet::RecordFlag::PTR, class_type: DNS::Packet::ClassFlag::Internet
ask_packet.transmissionId = Random.new.rand UInt16

udp_socket = UDPSocket.new
udp_socket.connect Socket::IPAddress.new "8.8.8.8", 53_i32
udp_socket.send ask_packet.to_slice
received_length, ip_address = udp_socket.receive buffer.to_slice

reply = DNS::Packet.from_io protocol_type: DNS::ProtocolType::UDP, io: IO::Memory.new(buffer.to_slice[0_i32, received_length])
STDOUT.puts [reply]
