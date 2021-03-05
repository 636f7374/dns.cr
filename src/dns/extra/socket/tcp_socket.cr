class TCPSocket < IPSocket
  def initialize(ip_address : IPAddress, dns_timeout = nil, connect_timeout = nil)
    Addrinfo.build_tcp ip_address do |addrinfo|
      super addrinfo.family, addrinfo.type, addrinfo.protocol
      connect(addrinfo, timeout: connect_timeout) do |error|
        close
        error
      end
    end
  end

  def self.new(host : String, port : Int32, dns_resolver : DNS::Resolver, connect_timeout : Int | Time::Span | Nil = nil) : TCPSocket
    fetch_type, ip_addresses = dns_resolver.getaddrinfo host: host, port: port
    raise Exception.new String.build { |io| io << "TCPSocket.new: " << "Unfortunately, DNS::Resolver.getaddrinfo! The resulting (" << fetch_type.to_s << ") IP list is empty!" } if ip_addresses.empty?

    connect_timeout_time_span = 10_i32.seconds
    connect_timeout_time_span = connect_timeout if connect_timeout.is_a? Time::Span
    connect_timeout_time_span = connect_timeout.seconds if connect_timeout.is_a? Int
    connect_timeout_time_span = 10_i32.seconds if 1_i32.seconds > connect_timeout_time_span

    attempt_connect_timeout_span = connect_timeout_time_span.dup
    attempt_connect_timeout_integer = (attempt_connect_timeout_span.to_i / ip_addresses.size) rescue 2_i64
    attempt_connect_timeout_integer = 2_i64 if 1_i64 > attempt_connect_timeout_integer
    attempt_connect_timeout_span = attempt_connect_timeout_integer.seconds

    before_time = Time.local
    ipv4_connection_failure_times = Atomic(Int32).new 0_i32
    ipv6_connection_failure_times = Atomic(Int32).new 0_i32

    ip_addresses.each_with_index do |ip_address, index|
      break if connect_timeout_time_span < (Time.local - before_time)

      case ip_address.family
      when .inet?
        next if ipv4_connection_failure_times.get == dns_resolver.options.socket.maximumTimesOfIpv4ConnectionFailureRetries
      when .inet6?
        next if ipv6_connection_failure_times.get == dns_resolver.options.socket.maximumNumberOfIpv6ConnectionFailureRetries
      end

      begin
        socket = new ip_address: ip_address, connect_timeout: attempt_connect_timeout_span
      rescue ex
        case ip_address.family
        when .inet?
          ipv4_connection_failure_times.add 1_i32
        when .inet6?
          ipv6_connection_failure_times.add 1_i32
        end

        raise ex if index.zero? && (1_i32 == ip_addresses.size)
        next if index != ip_addresses.size

        raise ex
      end

      if socket.closed?
        case ip_address.family
        when .inet?
          ipv4_connection_failure_times.add 1_i32
        when .inet6?
          ipv6_connection_failure_times.add 1_i32
        end

        next
      end

      return socket
    end

    raise Exception.new "TCPSocket.new: Tries to connect the DNS::Resolver.getaddrinfo! Returned results, But it still fails!"
  end
end
