class DNS::Resolver
  getter dnsServers : Set(Address)
  getter options : Options
  getter serviceMapperCaching : Caching::ServiceMapper
  getter ipAddressCaching : Caching::IPAddress
  getter packetCaching : Caching::Packet
  getter ipMapperCaching : Caching::IPAddress
  getter getAddrinfoProtector : GetAddrinfoProtector

  def initialize(@dnsServers : Set(Address), @options : Options = Options.new, @serviceMapperCaching : Caching::ServiceMapper = Caching::ServiceMapper.new, @ipAddressCaching : Caching::IPAddress = Caching::IPAddress.new, @packetCaching : Caching::Packet = Caching::Packet.new, @ipMapperCaching : Caching::IPAddress = Caching::IPAddress.new)
    @getAddrinfoProtector = GetAddrinfoProtector.new
  end

  def options : Options
    @options
  end

  def maximum_number_of_retries_for_ipv4_connection_failure(caller : Symbol?, delegator : Symbol) : UInt8
    options.socket.maximumNumberOfRetriesForIpv4ConnectionFailure
  end

  def maximum_number_of_retries_for_ipv6_connection_failure(caller : Symbol?, delegator : Symbol) : UInt8
    options.socket.maximumNumberOfRetriesForIpv6ConnectionFailure
  end

  def getaddrinfo(host : String, port : Int32 = 0_i32, caller : Symbol? = nil, answer_safety_first : Bool? = options.addrinfo.answerSafetyFirst, addrinfo_overridable : Bool? = nil) : Tuple(Symbol, FetchType, Array(Socket::IPAddress))
    # This function is used as an overridable.
    # E.g. Cloudflare.

    __getaddrinfo host: host, port: port, answer_safety_first: answer_safety_first, addrinfo_overridable: addrinfo_overridable
  end

  private def __getaddrinfo(host : String, port : Int32 = 0_i32, answer_safety_first : Bool? = options.addrinfo.answerSafetyFirst, addrinfo_overridable : Bool? = nil) : Tuple(Symbol, FetchType, Array(Socket::IPAddress))
    delegator, fetch_type, ip_addresses = getaddrinfo_raw host: host, port: port, answer_safety_first: answer_safety_first, addrinfo_overridable: addrinfo_overridable
    Tuple.new delegator, fetch_type, ip_addresses.map { |tuple| tuple.last }
  end

  def getaddrinfo_raw(host : String, port : Int32 = 0_i32, answer_safety_first : Bool? = options.addrinfo.answerSafetyFirst, addrinfo_overridable : Bool? = nil) : Tuple(Symbol, FetchType, Array(Tuple(ProtocolType, Time::Span, Socket::IPAddress)))
    service_mapper_entry = serviceMapperCaching.get? host: host, port: port
    answer_safety_first = service_mapper_entry.options.answerSafetyFirst if service_mapper_entry

    ip_address_local = Socket::IPAddress.new address: host, port: port rescue nil
    return Tuple.new :getaddrinfo_raw, FetchType::Local, [Tuple.new ProtocolType::HTTPS, 10_i32.seconds, ip_address_local] if ip_address_local

    ipMapperCaching.get_raw?(host: host, answer_safety_first: answer_safety_first, filter_type: options.addrinfo.filterType).try do |ip_addresses|
      return Tuple.new :getaddrinfo_raw, FetchType::Mapper, ip_addresses.to_a
    end

    ipAddressCaching.get_raw?(host: host, port: port, answer_safety_first: answer_safety_first, filter_type: options.addrinfo.filterType).try do |ip_addresses|
      return Tuple.new :getaddrinfo_raw, FetchType::Caching, ip_addresses.to_a
    end

    protect_getaddrinfo host: host if options.addrinfo.enableProtection

    ipAddressCaching.get_raw?(host: host, port: port, answer_safety_first: answer_safety_first, filter_type: options.addrinfo.filterType).try do |ip_addresses|
      getAddrinfoProtector.delete host: host if options.addrinfo.enableProtection
      return Tuple.new :getaddrinfo_raw, FetchType::Caching, ip_addresses.to_a
    end

    dns_servers = service_mapper_entry.try &.dnsServers
    dns_servers = nil if dns_servers.try &.empty?
    dns_servers = dnsServers unless dns_servers

    packets = getaddrinfo_query_ip_records dns_servers: dns_servers, host: host, class_type: Packet::ClassFlag::Internet
    ip_addresses = select_packet_answers_records_ip_addresses host: host, packets: packets, options: options

    caching_entry = ipAddressCaching.set host: host, ipv4_addresses: ip_addresses.first, ipv6_addresses: ip_addresses.last
    getAddrinfoProtector.delete host: host if options.addrinfo.enableProtection

    _ip_addresses = caching_entry.get_sort_ipaddresses answer_safety_first: answer_safety_first, filter_type: options.addrinfo.filterType, port: port
    Tuple.new :getaddrinfo_raw, FetchType::Remote, _ip_addresses
  end

  private def protect_getaddrinfo(host : String)
    return getAddrinfoProtector.set host: host unless getAddrinfoProtector.includes? host: host
    before_time = Time.local

    loop do
      break if options.addrinfo.protectionWaitingTime <= (Time.local - before_time)
      break unless getAddrinfoProtector.includes? host: host

      sleep 0.10_f32.seconds
    end
  end

  def service_mapper_caching_set(host : String, port : Int32, value : DNS::Address | Array(DNS::Address) | Set(DNS::Address), options : Caching::ServiceMapper::Entry::Options = Caching::ServiceMapper::Entry::Options.new)
    case value
    in DNS::Address
      serviceMapperCaching.set host: host, port: port, dns_server: value, options: options
    in Array(DNS::Address)
      serviceMapperCaching.set host: host, port: port, dns_servers: value, options: options
    in Set(DNS::Address)
      serviceMapperCaching.set host: host, port: port, dns_servers: value, options: options
    end
  end

  def ip_mapper_caching_set(host : String, ipv4_addresses : Set(Tuple(ProtocolType, Time::Span, Socket::IPAddress)), ipv6_addresses : Set(Tuple(ProtocolType, Time::Span, Socket::IPAddress)))
    ipMapperCaching.set host: host, ipv4_addresses: ipv4_addresses, ipv6_addresses: ipv6_addresses
  end

  def ip_mapper_caching_set(host : String, value : Tuple(ProtocolType, Time::Span, Socket::IPAddress) | Array(Tuple(ProtocolType, Time::Span, Socket::IPAddress)) | Set(Tuple(ProtocolType, Time::Span, Socket::IPAddress)))
    case value
    in Tuple(ProtocolType, Time::Span, Socket::IPAddress)
      ipMapperCaching.set host: host, ipv4_address: value, ipv6_address: nil
    in Array(Tuple(ProtocolType, Time::Span, Socket::IPAddress))
      ipMapperCaching.set host: host, ipv4_addresses: value, ipv6_addresses: [] of Tuple(ProtocolType, Time::Span, Socket::IPAddress)
    in Set(Tuple(ProtocolType, Time::Span, Socket::IPAddress))
      ipMapperCaching.set host: host, ipv4_addresses: value, ipv6_addresses: Set(Tuple(ProtocolType, Time::Span, Socket::IPAddress)).new
    end
  end

  def ip_address_caching_set(host : String, value : Tuple(ProtocolType, Time::Span, Socket::IPAddress) | Array(Tuple(ProtocolType, Time::Span, Socket::IPAddress)) | Set(Tuple(ProtocolType, Time::Span, Socket::IPAddress)))
    case value
    in Tuple(ProtocolType, Time::Span, Socket::IPAddress)
      ipAddressCaching.set host: host, ipv4_address: value, ipv6_address: nil
    in Array(Tuple(ProtocolType, Time::Span, Socket::IPAddress))
      ipAddressCaching.set host: host, ipv4_addresses: value, ipv6_addresses: [] of Tuple(ProtocolType, Time::Span, Socket::IPAddress)
    in Set(Tuple(ProtocolType, Time::Span, Socket::IPAddress))
      ipAddressCaching.set host: host, ipv4_addresses: value, ipv6_addresses: Set(Tuple(ProtocolType, Time::Span, Socket::IPAddress)).new
    end
  end

  private def select_packet_answers_records_ip_addresses(host : String, packets : Array(Packet), options : Options = Options.new) : Tuple(Set(Tuple(ProtocolType, Time::Span, Socket::IPAddress)), Set(Tuple(ProtocolType, Time::Span, Socket::IPAddress)))
    empty_tuple_set = Set(Tuple(ProtocolType, Time::Span, Socket::IPAddress)).new

    case options.addrinfo.filterType
    when .ipv4_only?
      ipv4_ipaddresses = Resolver.select_packet_answers_a_records_ip_addresses host: host, packets: packets, options: options
      Tuple.new ipv4_ipaddresses, empty_tuple_set
    when .ipv6_only?
      ipv6_ipaddresses = Resolver.select_packet_answers_aaaa_records_ip_addresses host: host, packets: packets, options: options
      Tuple.new empty_tuple_set, ipv6_ipaddresses
    else
      ipv4_ipaddresses = Resolver.select_packet_answers_a_records_ip_addresses host: host, packets: packets, options: options
      ipv6_ipaddresses = Resolver.select_packet_answers_aaaa_records_ip_addresses host: host, packets: packets, options: options

      Tuple.new ipv4_ipaddresses, ipv6_ipaddresses
    end
  end

  {% for record_type in ["a", "aaaa"] %}
  def self.select_packet_answers_{{record_type.id}}_records_ip_addresses(host : String, packets : Array(Packet), options : Options = Options.new) : Set(Tuple(ProtocolType, Time::Span, Socket::IPAddress))
    ip_addresses = [] of Tuple(ProtocolType, Time::Span, Socket::IPAddress)
    ip_addresses_protocol_type_list = Hash(Socket::IPAddress, ProtocolType).new

    packets.each do |packet| 
      records = packet.select_answers_{{record_type.id}}_records! name: host, options: options rescue nil
      next unless records

      records.each { |record| ip_addresses << Tuple.new packet.protocolType, record.ttl, record.address }
    end

    ip_addresses.each do |tuple|
      ip_address_protocol_type = ip_addresses_protocol_type_list[tuple.last]?
      next if ip_address_protocol_type.https? || ip_address_protocol_type.tls? if ip_address_protocol_type

      ip_addresses_protocol_type_list[tuple.last] = tuple.first
    end

    uniq_ip_addresses = ip_addresses.uniq { |tuple| tuple.last }

    value = uniq_ip_addresses.map do |tuple|
      protocol_type, ttl, ip_address = tuple
      Tuple.new (ip_addresses_protocol_type_list[tuple.last]? || tuple.first), ttl, ip_address
    end

    value.to_set
  end
  {% end %}

  def self.select_packet_answers_ip_records_ip_addresses(host : String, packets : Array(Packet), options : Options = Options.new) : Set(Tuple(ProtocolType, Time::Span, Socket::IPAddress))
    ip_addresses = [] of Tuple(ProtocolType, Time::Span, Socket::IPAddress)
    ip_addresses_protocol_type_list = Hash(Socket::IPAddress, ProtocolType).new

    packets.each do |packet|
      records = packet.select_answers_ip_records! name: host, options: options rescue nil
      next unless records

      records.each do |record|
        case record
        when Records::A, Records::AAAA
          ip_addresses << Tuple.new packet.protocolType, record.ttl, record.address
        end
      end
    end

    ip_addresses.each do |tuple|
      ip_address_protocol_type = ip_addresses_protocol_type_list[tuple.last]?
      next if ip_address_protocol_type.https? || ip_address_protocol_type.tls? if ip_address_protocol_type

      ip_addresses_protocol_type_list[tuple.last] = tuple.first
    end

    uniq_ip_addresses = ip_addresses.uniq { |tuple| tuple.last }

    value = uniq_ip_addresses.map do |tuple|
      protocol_type, ttl, ip_address = tuple
      Tuple.new (ip_addresses_protocol_type_list[tuple.last]? || tuple.first), ttl, ip_address
    end

    value.to_set
  end

  private def getaddrinfo_query_ip_records(dns_servers : Set(Address), host : String, class_type : Packet::ClassFlag = Packet::ClassFlag::Internet) : Array(Packet)
    return concurrent_getaddrinfo_query_ip_records dns_servers: dns_servers, host: host, class_type: class_type if options.addrinfo.concurrentQuery
    regular_getaddrinfo_query_ip_records dns_servers: dns_servers, host: host, class_type: class_type
  end

  private def concurrent_getaddrinfo_query_ip_records(dns_servers : Set(Address), host : String, class_type : Packet::ClassFlag = Packet::ClassFlag::Internet) : Array(Packet)
    concurrent_mutex = Mutex.new :unchecked
    concurrent_fibers = Set(Fiber).new
    reply_mutex = Mutex.new :unchecked
    reply_packets = Set(Array(Packet)).new

    main_concurrent_fiber = spawn do
      case options.addrinfo.queryType
      in .ipv4_only?
        ipv4_query_fiber = spawn do
          ipv4_packets = getaddrinfo_query_a_records dns_servers: dns_servers, host: host, class_type: class_type
          reply_mutex.synchronize { reply_packets << ipv4_packets }
        end

        concurrent_mutex.synchronize { concurrent_fibers << ipv4_query_fiber }
      in .ipv6_only?
        ipv6_query_fiber = spawn do
          ipv6_packets = getaddrinfo_query_aaaa_records dns_servers: dns_servers, host: host, class_type: class_type
          reply_mutex.synchronize { reply_packets << ipv6_packets }
        end

        concurrent_mutex.synchronize { concurrent_fibers << ipv6_query_fiber }
      in .both?
        ipv4_query_fiber = spawn do
          ipv4_packets = getaddrinfo_query_a_records dns_servers: dns_servers, host: host, class_type: class_type
          reply_mutex.synchronize { reply_packets << ipv4_packets }
        end

        concurrent_mutex.synchronize { concurrent_fibers << ipv4_query_fiber }

        ipv6_query_fiber = spawn do
          ipv6_packets = getaddrinfo_query_aaaa_records dns_servers: dns_servers, host: host, class_type: class_type
          reply_mutex.synchronize { reply_packets << ipv6_packets }
        end

        concurrent_mutex.synchronize { concurrent_fibers << ipv6_query_fiber }
      end
    end

    concurrent_mutex.synchronize { concurrent_fibers << main_concurrent_fiber }

    loop do
      all_dead = concurrent_mutex.synchronize { concurrent_fibers.all? { |fiber| fiber.dead? } }
      next sleep 0.25_f32.seconds unless all_dead
      break concurrent_mutex.synchronize { reply_packets.to_a.flatten }
    end
  end

  private def regular_getaddrinfo_query_ip_records(dns_servers : Set(Address), host : String, class_type : Packet::ClassFlag = Packet::ClassFlag::Internet) : Array(Packet)
    case options.addrinfo.queryType
    in .ipv4_only?
      getaddrinfo_query_a_records dns_servers: dns_servers, host: host, class_type: class_type
    in .ipv6_only?
      ipv6_packets = getaddrinfo_query_aaaa_records dns_servers: dns_servers, host: host, class_type: class_type
    in .both?
      packets = getaddrinfo_query_a_records dns_servers: dns_servers, host: host, class_type: class_type

      ipv6_packets = getaddrinfo_query_aaaa_records dns_servers: dns_servers, host: host, class_type: class_type
      ipv6_packets.each { |packet| packets << packet }

      packets
    end
  end

  {% for record_type in ["a", "aaaa"] %}
  private def getaddrinfo_query_{{record_type.id}}_records(dns_servers : Set(Address), host : String, class_type : Packet::ClassFlag = Packet::ClassFlag::Internet) : Array(Packet)
    getaddrinfo_query! dns_servers: dns_servers, host: host, record_type: Packet::RecordFlag::{{record_type.upcase.id}}, class_type: class_type
  end
  {% end %}

  private def getaddrinfo_query!(dns_servers : Set(Address), host : String, record_type : Packet::RecordFlag, class_type : Packet::ClassFlag = Packet::ClassFlag::Internet) : Array(Packet)
    ask_packet = Packet.create_getaddrinfo_ask protocol_type: ProtocolType::UDP, name: host, record_type: record_type, class_type: class_type
    resolve! dns_servers: dns_servers, ask_packet: ask_packet
  end

  def resolve(host : String, record_type : Packet::RecordFlag, ask_packet : Packet) : Tuple(FetchType, Array(Packet))
    packetCaching.get?(host: host, record_type: record_type).try { |packets| return Tuple.new FetchType::Caching, packets }

    packets = resolve! dns_servers: dnsServers, ask_packet: ask_packet
    packetCaching.set host: host, record_type: record_type, packets: packets

    Tuple.new FetchType::Remote, packets
  end

  private def resolve!(dns_servers : Set(Address), ask_packet : Packet) : Array(Packet)
    return concurrent_resolve dns_servers: dns_servers, ask_packet: ask_packet if options.addrinfo.concurrentQuery
    regular_resolve dns_servers: dns_servers, ask_packet: ask_packet
  end

  private def concurrent_resolve(dns_servers : Set(Address), ask_packet : Packet) : Array(Packet)
    concurrent_mutex = Mutex.new :unchecked
    concurrent_fibers = Set(Fiber).new
    reply_mutex = Mutex.new :unchecked
    reply_packets = Set(Packet).new

    main_concurrent_fiber = spawn do
      dns_servers.each do |dns_server|
        concurrent_fiber = spawn do
          socket = dns_server.create_socket! rescue nil
          next unless socket

          dup_ask_packet = ask_packet.dup
          dup_ask_packet.transmissionId = Random.new.rand UInt16

          dup_ask_packet.protocolType = dns_server.protocolType
          dup_ask_packet.protocolType = ProtocolType::UDP if dns_server.protocolType.http? || dns_server.protocolType.https?

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
            reply.try { |_reply| reply_mutex.synchronize { reply_packets << _reply } }
          when TCPSocket, OpenSSL::SSL::Socket::Client
            case socket
            in TCPSocket
              reply = resolve! dns_server: dns_server, socket: socket, ask_packet: dup_ask_packet, protocol_type: dns_server.protocolType rescue nil
            in OpenSSL::SSL::Socket::Client
              reply = resolve! dns_server: dns_server, socket: socket, ask_packet: dup_ask_packet, protocol_type: dns_server.protocolType rescue nil
            in UDPSocket
            in IO
            end

            socket.close rescue nil
            reply.try { |_reply| reply_mutex.synchronize { reply_packets << _reply } }
          else
            socket.close rescue nil
          end
        end

        concurrent_mutex.synchronize { concurrent_fibers << concurrent_fiber }
      end
    end

    concurrent_mutex.synchronize { concurrent_fibers << main_concurrent_fiber }

    loop do
      all_dead = concurrent_mutex.synchronize { concurrent_fibers.all? { |fiber| fiber.dead? } }
      next sleep 0.25_f32.seconds unless all_dead
      break reply_mutex.synchronize { reply_packets.to_a }
    end
  end

  private def regular_resolve(dns_servers : Set(Address), ask_packet : Packet) : Array(Packet)
    reply_packets = Set(Packet).new

    dns_servers.each do |dns_server|
      socket = dns_server.create_socket! rescue nil
      next unless socket

      dup_ask_packet = ask_packet.dup
      dup_ask_packet.transmissionId = Random.new.rand UInt16

      dup_ask_packet.protocolType = dns_server.protocolType
      dup_ask_packet.protocolType = ProtocolType::UDP if dns_server.protocolType.http? || dns_server.protocolType.https?

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
        reply.try { |_reply| reply_packets << _reply }
      when TCPSocket, OpenSSL::SSL::Socket::Client
        case socket
        in TCPSocket
          reply = resolve! dns_server: dns_server, socket: socket, ask_packet: dup_ask_packet, protocol_type: dns_server.protocolType rescue nil
        in OpenSSL::SSL::Socket::Client
          reply = resolve! dns_server: dns_server, socket: socket, ask_packet: dup_ask_packet, protocol_type: dns_server.protocolType rescue nil
        in UDPSocket
        in IO
        end

        socket.close rescue nil
        reply.try { |_reply| reply_packets << _reply }
      else
        socket.close rescue nil
      end
    end

    reply_packets.to_a
  end

  private def resolve!(socket : UDPSocket, ask_packet : Packet, protocol_type : ProtocolType) : Packet
    buffer = uninitialized UInt8[4096_i32]
    socket.send ask_packet.to_slice

    received_length, ip_address = socket.receive buffer.to_slice
    raise Exception.new "Resolver.resolve!: DNS query failed, zero bytes have been received!" if received_length.zero?

    memory = IO::Memory.new buffer.to_slice[0_i32, received_length]
    reply = Packet.from_io protocol_type: protocol_type, io: memory, options: options

    raise Exception.new String.build { |io| io << "Resolver.resolve!: DNS query failed, Possibly because the server is not responding!" } unless reply.arType.reply?
    raise Exception.new String.build { |io| io << "Resolver.resolve!: The transmissionId of the reply packet does not match the ask transmissionId!" } if ask_packet.transmissionId != reply.transmissionId
    raise Exception.new String.build { |io| io << "Resolver.resolve!: The errorType of the reply packet is not Packet::ErrorFlag::NoError!" } unless reply.errorType.no_error?

    reply
  end

  private def resolve!(dns_server : Address, socket : TCPSocket | OpenSSL::SSL::Socket::Client, ask_packet : Packet, protocol_type : ProtocolType) : Packet
    case dns_server
    when Address::HTTP, Address::HTTPS
      request = HTTP::Request.new method: dns_server.method, resource: String.build { |io| io << dns_server.resource << Base64.strict_encode(String.new(ask_packet.to_slice)) }
      request.headers = dns_server.headers
      request.to_io io: socket

      HTTP::Client::Response.from_io io: socket, ignore_body: true
      _protocol_type = ProtocolType::UDP
    else
      socket.write ask_packet.to_slice
      _protocol_type = protocol_type
    end

    buffer = uninitialized UInt8[4096_i32]
    read_length = socket.read buffer.to_slice
    raise Exception.new "Resolver.resolve!: DNS query failed, zero bytes have been read!" if read_length.zero?

    memory = IO::Memory.new buffer.to_slice[0_i32, read_length]
    reply = Packet.from_io protocol_type: _protocol_type, io: memory, options: options

    raise Exception.new String.build { |io| io << "Resolver.resolve!: DNS query failed, Possibly because the server is not responding!" } unless reply
    raise Exception.new String.build { |io| io << "Resolver.resolve!: The arType of the reply packet is not ARType::Reply!" } unless reply.arType.reply?
    raise Exception.new String.build { |io| io << "Resolver.resolve!: The transmissionId of the reply packet does not match the ask transmissionId!" } if ask_packet.transmissionId != reply.transmissionId
    raise Exception.new String.build { |io| io << "Resolver.resolve!: The errorType of the reply packet is not Packet::ErrorFlag::NoError!" } unless reply.errorType.no_error?

    reply.protocolType = ProtocolType::HTTPS if protocol_type.https?

    reply
  end

  def __create_socket_exception_call(ip_address : Socket::IPAddress, exception : Exception)
    # This function is used as an overridable.
    # E.g. Cloudflare.
  end
end

require "http/request"
require "./resolver/*"
require "./caching/*"
