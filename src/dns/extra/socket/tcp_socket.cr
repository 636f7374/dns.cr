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
    raise Exception.new String.build { |io| io << "TCPSocket.new: Unfortunately, DNS::Resolver.getaddrinfo! The host: (" << host << ") & fetchType: (" << fetch_type << ")" << " IPAddress result is empty!" } if ip_addresses.empty?

    maximum_number_of_retries_for_per_ip_address = dns_resolver.options.socket.maximumNumberOfRetriesForPerIpAddress
    maximum_number_of_retries_for_per_ip_address = 1_u8 if maximum_number_of_retries_for_per_ip_address <= 0_u8

    connect_timeout_time_span = 10_i32.seconds
    connect_timeout_time_span = connect_timeout if connect_timeout.is_a? Time::Span
    connect_timeout_time_span = connect_timeout.seconds if connect_timeout.is_a? Int
    connect_timeout_time_span = 10_i32.seconds if 1_i32.seconds > connect_timeout_time_span

    attempt_connect_timeout_span = connect_timeout_time_span.dup
    attempt_connect_timeout_integer = (attempt_connect_timeout_span.to_i / ip_addresses.size) rescue 2_i64
    attempt_connect_timeout_integer = 2_i64 if 1_i64 > attempt_connect_timeout_integer
    attempt_connect_timeout_span = attempt_connect_timeout_integer.seconds

    ipv4_connection_failure_counter = Atomic(Int32).new 0_i32
    ipv6_connection_failure_counter = Atomic(Int32).new 0_i32
    starting_time = Time.local

    ip_addresses.each_with_index do |ip_address, index|
      break if connect_timeout_time_span <= (Time.local - starting_time)

      case ip_address.family
      when .inet?
        next if ipv4_connection_failure_counter.get == dns_resolver.options.socket.maximumNumberOfRetriesForIpv4ConnectionFailure
      when .inet6?
        next if ipv6_connection_failure_counter.get == dns_resolver.options.socket.maximumNumberOfRetriesForIpv6ConnectionFailure
      end

      begin
        socket = maximum_number_of_retries_for_per_ip_address.times do |time|
          _starting_time = Time.local

          begin
            _socket = new ip_address: ip_address, connect_timeout: attempt_connect_timeout_span
          rescue ex
            unless (time + 1_i32) == maximum_number_of_retries_for_per_ip_address
              next if ex.is_a? IO::Error && "Error reading socket: Connection reset by peer" == ex.message && ((Time.local - _starting_time) < 1_i32.seconds)
            end

            raise ex
          end

          next if _socket.closed? unless (time + 1_i32) == maximum_number_of_retries_for_per_ip_address
          break _socket
        end

        raise Exception.new String.build { |io| io << "TCPSocket.new: IPAddress: (" << ip_address << ") connection failed (Nil)!" } unless socket
      rescue ex
        case ip_address.family
        when .inet?
          ipv4_connection_failure_counter.add 1_i32
        when .inet6?
          ipv6_connection_failure_counter.add 1_i32
        end

        raise ex if index.zero? && (1_i32 == ip_addresses.size)
        next if index != ip_addresses.size

        raise ex
      end

      if socket.closed?
        case ip_address.family
        when .inet?
          ipv4_connection_failure_counter.add 1_i32
        when .inet6?
          ipv6_connection_failure_counter.add 1_i32
        end

        next
      end

      return socket
    end

    raise Exception.new String.build { |io| io << "TCPSocket.new: Tries to connect the DNS::Resolver.getaddrinfo! address: (" << host << ':' << port << ") & fetchType: (" << fetch_type << ") & count: (" << ip_addresses.size << ") IP addresses, But still failed to connect!" }
  end
end
