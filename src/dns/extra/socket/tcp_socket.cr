class TCPSocket < IPSocket
  def initialize(ip_address : IPAddress, dns_timeout = nil, connect_timeout = nil, blocking = false)
    Addrinfo.build_tcp ip_address: ip_address do |addrinfo|
      super addrinfo.family, addrinfo.type, addrinfo.protocol, blocking

      connect(addrinfo, timeout: connect_timeout) do |error|
        close
        error
      end
    end
  end

  def self.new(host : String, port : Int32, dns_resolver : DNS::Resolver, connect_timeout : Int | Time::Span | Nil = nil, caller : Symbol? = nil, answer_safety_first : Bool? = nil, addrinfo_overridable : Bool? = nil) : TCPSocket
    delegator, fetch_type, ip_addresses = dns_resolver.getaddrinfo host: host, port: port, caller: caller, answer_safety_first: answer_safety_first, addrinfo_overridable: addrinfo_overridable
    raise Exception.new String.build { |io| io << "TCPSocket.new: Unfortunately, DNS::Resolver.getaddrinfo! The host: (" << host << ") & fetchType: (" << fetch_type << ")" << " IPAddress result is empty!" } if ip_addresses.empty?

    connect_timeout_time_span = case _connect_timeout = connect_timeout
                                in Time::Span
                                  _connect_timeout
                                in Int
                                  _connect_timeout.seconds
                                in Nil
                                  10_i32.seconds
                                end

    ipv4_connection_failure_counter = Atomic(Int32).new 0_i32
    ipv6_connection_failure_counter = Atomic(Int32).new 0_i32

    ip_addresses.each_with_index do |ip_address, index|
      ip_address = Socket::IPAddress.new address: ip_address.address, port: port if ip_address.port.zero?

      case ip_address.family
      when .inet?
        next if ipv4_connection_failure_counter.get == dns_resolver.maximum_ipv4_attempts caller: caller, delegator: delegator
      when .inet6?
        next if ipv6_connection_failure_counter.get == dns_resolver.maximum_ipv6_attempts caller: caller, delegator: delegator
      end

      begin
        socket = attempt_create_socket! dns_resolver: dns_resolver, caller: caller, delegator: delegator, fetch_type: fetch_type, ip_address: ip_address, connect_timeout: connect_timeout_time_span
      rescue ex
        dns_resolver.__create_socket_exception_call ip_address: ip_address, exception: ex

        case ip_address.family
        when .inet?
          ipv4_connection_failure_counter.add value: 1_i32
        when .inet6?
          ipv6_connection_failure_counter.add value: 1_i32
        end

        raise ex if index.zero? && (1_i32 == ip_addresses.size)
        next unless index == ip_addresses.size

        raise ex
      end

      if socket.closed?
        case ip_address.family
        when .inet?
          ipv4_connection_failure_counter.add value: 1_i32
        when .inet6?
          ipv6_connection_failure_counter.add value: 1_i32
        end

        next
      end

      return socket
    end

    raise Exception.new String.build { |io| io << "TCPSocket.new: Tries to connect the DNS::Resolver.getaddrinfo! address: (" << host << ':' << port << ") & fetchType: (" << fetch_type << ") & count: (" << ip_addresses.size << ") IP addresses, But still failed to connect!" }
  end

  private def self.attempt_create_socket!(dns_resolver : DNS::Resolver, caller : Symbol?, delegator : Symbol, fetch_type : DNS::FetchType, ip_address : Socket::IPAddress, connect_timeout : Time::Span) : TCPSocket
    new ip_address: ip_address, connect_timeout: connect_timeout
  end
end
