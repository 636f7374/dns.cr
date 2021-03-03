class DNS::Resolver
  getter dnsServers : Set(Address)
  property options : Options
  getter ipAddressCaching : Caching::IPAddress
  getter packetCaching : Caching::Packet
  getter getAddrinfoProtector : GetAddrinfoProtector
  getter mutex : Mutex

  def initialize(@dnsServers : Set(Address), @options : Options = Options.new, @ipAddressCaching : Caching::IPAddress = Caching::IPAddress.new, @packetCaching : Caching::Packet = Caching::Packet.new)
    @getAddrinfoProtector = GetAddrinfoProtector.new
    @mutex = Mutex.new :unchecked
  end

  def getaddrinfo(host : String, port : Int32 = 0_i32) : Tuple(FetchType, Array(Socket::IPAddress))
    ip_address_local = Socket::IPAddress.new address: host, port: port rescue nil
    return Tuple.new FetchType::Local, [ip_address_local] if ip_address_local

    ipAddressCaching.get?(host: host, port: port).try { |ip_addresses| return Tuple.new FetchType::Caching, ip_addresses }
    set_getaddrinfo_protect host: host if options.addrinfo.enableProtection
    ipAddressCaching.get?(host: host, port: port).try do |ip_addresses|
      getAddrinfoProtector.delete host: host if options.addrinfo.enableProtection
      return Tuple.new FetchType::Caching, ip_addresses
    end

    packets = getaddrinfo_query_ip_records dns_servers: dnsServers, host: host, class_type: Packet::ClassFlag::Internet
    ip_addresses = select_packet_answers_records_ip_addresses host: host, packets: packets, maximum_depth: options.addrinfo.maximumCanonicalNameDepth

    ipAddressCaching.set host: host, ip_addresses: ip_addresses
    getAddrinfoProtector.delete host: host if options.addrinfo.enableProtection

    return Tuple.new FetchType::Server, ip_addresses if port.zero?
    Tuple.new FetchType::Server, ip_addresses.map { |ip_address| Socket::IPAddress.new address: ip_address.address, port: port }
  end

  private def set_getaddrinfo_protect(host : String)
    return getAddrinfoProtector.set host: host unless getAddrinfoProtector.includes? host: host
    before_time = Time.local

    loop do
      break if options.addrinfo.protectionWaitingTime <= (Time.local - before_time)
      break unless getAddrinfoProtector.includes? host: host

      sleep 0.10_f32.seconds
    end
  end

  private def select_packet_answers_records_ip_addresses(host : String, packets : Array(Packet), maximum_depth : Int32 = 64_i32) : Array(Socket::IPAddress)
    packets = packets.sort { |x, y| ~(x.protocolType <=> y.protocolType) } if options.addrinfo.answerSafetyFirst

    case options.addrinfo.filterType
    in .ipv4_only?
      Resolver.select_packet_answers_a_records_ip_addresses host: host, packets: packets, maximum_depth: maximum_depth
    in .ipv6_only?
      Resolver.select_packet_answers_aaaa_records_ip_addresses host: host, packets: packets, maximum_depth: maximum_depth
    in .both?
      Resolver.select_packet_answers_ip_records_ip_addresses host: host, packets: packets, maximum_depth: maximum_depth
    end
  end

  {% for record_type in ["a", "aaaa"] %}
  def self.select_packet_answers_{{record_type.id}}_records_ip_addresses(host : String, packets : Array(Packet), maximum_depth : Int32 = 64_i32) : Array(Socket::IPAddress)
    ip_addresses = [] of Socket::IPAddress

    packets.each do |packet| 
      records = packet.select_answers_{{record_type.id}}_records! name: host, maximum_depth: maximum_depth rescue nil
      next unless records

      records.each { |record| ip_addresses << record.address }
    end

    ip_addresses.uniq
  end
  {% end %}

  def self.select_packet_answers_ip_records_ip_addresses(host : String, packets : Array(Packet), maximum_depth : Int32 = 64_i32) : Array(Socket::IPAddress)
    ip_addresses = [] of Socket::IPAddress

    packets.each do |packet|
      records = packet.select_answers_ip_records! name: host, maximum_depth: maximum_depth rescue nil
      next unless records

      records.each do |record|
        case record
        when Records::A, Records::AAAA
          ip_addresses << record.address
        end
      end
    end

    ip_addresses.uniq
  end

  private def getaddrinfo_query_ip_records(dns_servers : Set(Address), host : String, class_type : Packet::ClassFlag = Packet::ClassFlag::Internet) : Array(Packet)
    return concurrent_getaddrinfo_query_ip_records dns_servers: dns_servers, host: host, class_type: class_type if options.addrinfo.concurrentQuery
    regular_getaddrinfo_query_ip_records dns_servers: dns_servers, host: host, class_type: class_type
  end

  private def concurrent_getaddrinfo_query_ip_records(dns_servers : Set(Address), host : String, class_type : Packet::ClassFlag = Packet::ClassFlag::Internet) : Array(Packet)
    concurrent_mutex = Mutex.new :unchecked
    concurrent_fibers = Set(Fiber).new
    reply_mutex = Mutex.new :unchecked
    reply_packets = [] of Array(Packet)

    ipv4_query_fiber = spawn do
      ipv4_packets = getaddrinfo_query_a_records dns_servers: dns_servers, host: host, class_type: class_type
      reply_mutex.synchronize { reply_packets << ipv4_packets }
    end

    concurrent_mutex.synchronize { concurrent_fibers << ipv4_query_fiber }

    ipv6_query_fiber = spawn do
      next unless options.addrinfo.queryIpv6
      ipv6_packets = getaddrinfo_query_aaaa_records dns_servers: dns_servers, host: host, class_type: class_type
      reply_mutex.synchronize { reply_packets << ipv6_packets }
    end

    concurrent_mutex.synchronize { concurrent_fibers << ipv6_query_fiber }

    loop do
      all_dead = concurrent_mutex.synchronize { concurrent_fibers.all? { |fiber| fiber.dead? } }
      next sleep 0.25_f32.seconds unless all_dead
      break concurrent_mutex.synchronize { reply_packets.flatten }
    end
  end

  private def regular_getaddrinfo_query_ip_records(dns_servers : Set(Address), host : String, class_type : Packet::ClassFlag = Packet::ClassFlag::Internet) : Array(Packet)
    packets = getaddrinfo_query_a_records dns_servers: dns_servers, host: host, class_type: class_type

    if options.addrinfo.queryIpv6
      ipv6_packets = getaddrinfo_query_aaaa_records dns_servers: dns_servers, host: host, class_type: class_type
      ipv6_packets.each { |packet| packets << packet }
    end

    packets
  end

  {% for record_type in ["a", "aaaa"] %}
  private def getaddrinfo_query_{{record_type.id}}_records(dns_servers : Set(Address), host : String, class_type : Packet::ClassFlag = Packet::ClassFlag::Internet) : Array(Packet)
    getaddrinfo! dns_servers: dns_servers, host: host, record_type: Packet::RecordFlag::{{record_type.upcase.id}}, class_type: class_type
  end
  {% end %}

  private def getaddrinfo!(dns_servers : Set(Address), host : String, record_type : Packet::RecordFlag, class_type : Packet::ClassFlag = Packet::ClassFlag::Internet) : Array(Packet)
    ask_packet = Packet.create_getaddrinfo_ask protocol_type: ProtocolType::UDP, name: host, record_type: record_type, class_type: class_type
    resolve! dns_servers: dns_servers, ask_packet: ask_packet
  end

  def resolve(host : String, record_type : Packet::RecordFlag, ask_packet : Packet) : Tuple(FetchType, Array(Packet))
    packetCaching.get?(host: host, record_type: record_type).try { |packets| return Tuple.new FetchType::Caching, packets }

    packets = resolve! dns_servers: dnsServers, ask_packet: ask_packet
    packetCaching.set host: host, record_type: record_type, packets: packets

    Tuple.new FetchType::Server, packets
  end

  private def resolve!(dns_servers : Set(Address), ask_packet : Packet) : Array(Packet)
    return concurrent_resolve dns_servers: dns_servers, ask_packet: ask_packet if options.addrinfo.concurrentQuery
    regular_resolve dns_servers: dns_servers, ask_packet: ask_packet
  end

  private def concurrent_resolve(dns_servers : Set(Address), ask_packet : Packet) : Array(Packet)
    concurrent_mutex = Mutex.new :unchecked
    concurrent_fibers = Set(Fiber).new
    reply_mutex = Mutex.new :unchecked
    reply_packets = [] of Packet

    dns_servers.each do |dns_server|
      concurrent_fiber = spawn do
        tuple_context_socket = dns_server.create_socket! rescue nil
        next unless tuple_context_socket

        tls_context, socket = tuple_context_socket
        dup_ask_packet = ask_packet.dup
        dup_ask_packet.protocolType = dns_server.protocolType
        dup_ask_packet.transmissionId = Random.new.rand UInt16

        case socket
        when UDPSocket
          reply = resolve! socket: socket, ask_packet: dup_ask_packet, protocol_type: dns_server.protocolType rescue nil

          unless reply
            options.addrinfo.maximumNumberOfMismatchRetries.times do
              reply = resolve! socket: socket, ask_packet: dup_ask_packet, protocol_type: dns_server.protocolType rescue nil
              break if reply
            end
          end

          socket.close rescue nil
          next unless reply
          concurrent_mutex.synchronize { reply_packets << reply }
        when TCPSocket, OpenSSL::SSL::Socket::Client
          if socket.is_a? OpenSSL::SSL::Socket::Client
            tls_context.try &.skip_finalize = true
            socket.skip_finalize = true
          end

          case socket
          in TCPSocket
            reply = resolve! socket: socket, ask_packet: dup_ask_packet, protocol_type: dns_server.protocolType rescue nil
          in OpenSSL::SSL::Socket::Client
            reply = resolve! socket: socket, ask_packet: dup_ask_packet, protocol_type: dns_server.protocolType rescue nil
          in UDPSocket
          in IO
          end

          socket.close rescue nil

          if socket.is_a? OpenSSL::SSL::Socket::Client
            tls_context.try &.free
            socket.free
          end

          next unless reply
          reply_mutex.synchronize { reply_packets << reply }
        else
          tls_context.try &.skip_finalize = true
          tls_context.try &.free

          socket.close rescue nil
        end
      end

      concurrent_mutex.synchronize { concurrent_fibers << concurrent_fiber }
    end

    loop do
      all_dead = concurrent_mutex.synchronize { concurrent_fibers.all? { |fiber| fiber.dead? } }
      next sleep 0.25_f32.seconds unless all_dead
      break concurrent_mutex.synchronize { reply_packets }
    end
  end

  private def regular_resolve(dns_servers : Set(Address), ask_packet : Packet) : Array(Packet)
    reply_packets = [] of Packet

    dns_servers.each do |dns_server|
      tuple_context_socket = dns_server.create_socket! rescue nil
      next unless tuple_context_socket

      tls_context, socket = tuple_context_socket
      dup_ask_packet = ask_packet.dup
      dup_ask_packet.protocolType = dns_server.protocolType
      dup_ask_packet.transmissionId = Random.new.rand UInt16

      case socket
      when UDPSocket
        reply = resolve! socket: socket, ask_packet: dup_ask_packet, protocol_type: dns_server.protocolType rescue nil

        unless reply
          options.addrinfo.maximumNumberOfMismatchRetries.times do
            reply = resolve! socket: socket, ask_packet: dup_ask_packet, protocol_type: dns_server.protocolType rescue nil
            break if reply
          end
        end

        socket.close rescue nil
        next unless reply
        reply_packets << reply
      when TCPSocket, OpenSSL::SSL::Socket::Client
        if socket.is_a? OpenSSL::SSL::Socket::Client
          tls_context.try &.skip_finalize = true
          socket.skip_finalize = true
        end

        case socket
        in TCPSocket
          reply = resolve! socket: socket, ask_packet: dup_ask_packet, protocol_type: dns_server.protocolType rescue nil
        in OpenSSL::SSL::Socket::Client
          reply = resolve! socket: socket, ask_packet: dup_ask_packet, protocol_type: dns_server.protocolType rescue nil
        in UDPSocket
        in IO
        end

        socket.close rescue nil

        if socket.is_a? OpenSSL::SSL::Socket::Client
          tls_context.try &.free
          socket.free
        end

        next unless reply
        reply_packets << reply
      else
        tls_context.try &.skip_finalize = true
        tls_context.try &.free

        socket.close rescue nil
      end
    end

    reply_packets
  end

  private def resolve!(socket : UDPSocket, ask_packet : Packet, protocol_type : ProtocolType) : Packet
    buffer = uninitialized UInt8[4096_i32]
    socket.send ask_packet.to_slice

    received_length, ip_address = socket.receive buffer.to_slice
    raise Exception.new "Resolver.resolve!: DNS query failed, zero bytes have been received!" if received_length.zero?

    memory = IO::Memory.new buffer.to_slice[0_i32, received_length]
    reply = Packet.from_io protocol_type: protocol_type, io: memory

    raise Exception.new String.build { |io| io << "Resolver.resolve!: DNS query failed, Possibly because the server is not responding!" } unless reply.arType.reply?
    raise Exception.new String.build { |io| io << "Resolver.resolve!: The transmissionId of the reply packet does not match the ask transmissionId!" } if ask_packet.transmissionId != reply.transmissionId
    raise Exception.new String.build { |io| io << "Resolver.resolve!: The errorType of the reply packet is not Packet::ErrorFlag::NoError!" } unless reply.errorType.no_error?

    reply
  end

  private def resolve!(socket : TCPSocket | OpenSSL::SSL::Socket::Client, ask_packet : Packet, protocol_type : ProtocolType) : Packet
    buffer = uninitialized UInt8[4096_i32]
    socket.write ask_packet.to_slice

    read_length = socket.read buffer.to_slice
    raise Exception.new "Resolver.resolve!: DNS query failed, zero bytes have been read!" if read_length.zero?

    memory = IO::Memory.new buffer.to_slice[0_i32, read_length]
    reply = Packet.from_io protocol_type: protocol_type, io: memory
    raise Exception.new String.build { |io| io << "Resolver.resolve!: DNS query failed, Possibly because the server is not responding!" } unless reply
    raise Exception.new String.build { |io| io << "Resolver.resolve!: The arType of the reply packet is not ARType::Reply!" } unless reply.arType.reply?
    raise Exception.new String.build { |io| io << "Resolver.resolve!: The transmissionId of the reply packet does not match the ask transmissionId!" } if ask_packet.transmissionId != reply.transmissionId
    raise Exception.new String.build { |io| io << "Resolver.resolve!: The errorType of the reply packet is not Packet::ErrorFlag::NoError!" } unless reply.errorType.no_error?

    reply
  end
end

require "./resolver/*"
require "./caching/*"
