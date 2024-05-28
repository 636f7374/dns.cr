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
    raise Exception.new String.build { |io| io << "TCPSocket.new: DNS::Resolver.getaddrinfo! The host: (" << host << ") & fetchType: (" << fetch_type << ")" << " IPAddress result is empty!" } if ip_addresses.empty?

    _connect_timeout = case __connect_timeout = connect_timeout
                       in Time::Span
                         __connect_timeout
                       in Int
                         __connect_timeout.seconds
                       in Nil
                         10_i32.seconds
                       end

    ipv4_failure_counter = Atomic(UInt8).new value: 0_u8
    ipv6_failure_counter = Atomic(UInt8).new value: 0_u8

    failure_counter_callback = ->(family : Socket::Family, method : Symbol) do
      case method
      when :get
        family.inet? ? ipv4_failure_counter.get : ipv6_failure_counter.get
      when :add
        family.inet? ? ipv4_failure_counter.add(value: 1_u8) : ipv6_failure_counter.add(value: 1_u8)
      else
        UInt8::MAX
      end
    end

    loop do
      begin
        socket = attempt_create_socket dns_resolver: dns_resolver, caller: caller, delegator: delegator, fetch_type: fetch_type, ip_addresses: ip_addresses, port: port, connect_timeout: _connect_timeout, failure_counter: failure_counter_callback
      rescue exception
      end

      # E.g. (Some Domains have only one IP address.)
      # It is possible that the connection failed due to connect_timeout.
      # E.g. (one IP address and 5 seconds connect_timeout) or (Four IP addresses and 10 seconds connect_timeout).
      # Maybe support customization via Options in the future (to be implemented).

      if exception && (1_i32 == ip_addresses.size)
        first_family = (ip_addresses.first?.try &.family || Socket::Family::INET)

        case first_family
        when .inet?
          maximum_ipv4_attempts = dns_resolver.maximum_ipv4_attempts caller: caller, delegator: delegator

          unless maximum_ipv4_attempts.zero?
            next if ipv4_failure_counter.get < maximum_ipv4_attempts
          end
        when .inet6?
          maximum_ipv6_attempts = dns_resolver.maximum_ipv6_attempts caller: caller, delegator: delegator

          unless maximum_ipv6_attempts
            next if ipv6_failure_counter.get < maximum_ipv6_attempts
          end
        end
      end

      return socket if socket
      _exception = exception = Exception.new(message: String.build { |io| io << "TCPSocket.new: Tries to connect address: (" << host << ':' << port << ") & fetchType: (" << fetch_type << ") & ipCounts: (" << ip_addresses.size << "), But still failed to connect!" })
      exception = _exception if exception.try &.message == "TCPSocket.attempt_create_socket: connect failed!"
      raise exception || _exception
    end
  end

  private def self.attempt_create_socket(dns_resolver : DNS::Resolver, caller : Symbol?, delegator : Symbol, fetch_type : DNS::FetchType, ip_addresses : Array(Socket::IPAddress), port : Int32, connect_timeout : Time::Span, failure_counter : Proc(Socket::Family, Symbol, UInt8)) : TCPSocket
    exception = nil

    ip_addresses.each_with_index do |ip_address, index|
      case ip_address.family
      when .inet?
        next if failure_counter.call(Socket::Family::INET, :get) == dns_resolver.maximum_ipv4_attempts(caller: caller, delegator: delegator)
      when .inet6?
        next if failure_counter.call(Socket::Family::INET6, :get) == dns_resolver.maximum_ipv6_attempts(caller: caller, delegator: delegator)
      end

      ip_address = Socket::IPAddress.new address: ip_address.address, port: port if ip_address.port.zero?

      begin
        socket = new ip_address: ip_address, connect_timeout: connect_timeout
        return socket unless socket.closed?
      rescue exception
        dns_resolver.__create_socket_exception_call ip_address: ip_address, exception: exception
      end

      if socket.try &.closed? || exception
        case ip_address.family
        when .inet?
          failure_counter.call(Socket::Family::INET, :add)
        when .inet6?
          failure_counter.call(Socket::Family::INET6, :add)
        end
      end

      raise exception if (1_i32 == ip_addresses.size) && exception
      next unless index == ip_addresses.size
    end

    raise exception || Exception.new(message: "TCPSocket.attempt_create_socket: connect failed!")
  end
end
