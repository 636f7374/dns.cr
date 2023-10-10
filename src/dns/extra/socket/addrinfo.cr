class Socket
  struct Addrinfo
    def self.build_addrinfo(ip_address : IPAddress, family : Family, type : Type, protocol : Protocol, &block : Addrinfo ->)
      {% if flag?(:wasm32) %}
        raise NotImplementedError.new "Socket::Addrinfo.build_addrinfo"
      {% else %}
        ip_address_size = ip_address.size.to_u8
        service = ip_address.port

        hints = LibC::Addrinfo.new
        hints.ai_family = (ip_address.family || Family::UNSPEC).to_i32
        hints.ai_socktype = type
        hints.ai_protocol = protocol
        hints.ai_flags = 0_u8
        hints.ai_addrlen = ip_address_size
        hints.ai_addr = ip_address.to_unsafe

        if service.is_a? Int
          hints.ai_flags |= LibC::AI_NUMERICSERV
        end

        # On OS X < 10.12, the libsystem implementation of getaddrinfo segfaults
        # if AI_NUMERICSERV is set, and servname is NULL or 0.
        {% if flag?(:darwin) %}
          if (service == 0_i32 || service.nil?) && (hints.ai_flags & LibC::AI_NUMERICSERV)
            hints.ai_flags |= LibC::AI_NUMERICSERV
          end
        {% end %}

        {% if flag?(:win32) %}
          if service.is_a?(Int) && service < 0_i32
            raise Error.from_os_error(nil, WinError::WSATYPE_NOT_FOUND, domain: ip_address.address, type: type, protocol: protocol, service: service)
          end
        {% end %}

        yield new pointerof(hints)
      {% end %}
    end

    def self.build_tcp(ip_address : IPAddress, family = Family::UNSPEC)
      build_addrinfo ip_address: ip_address, family: family, type: Type::STREAM, protocol: Protocol::TCP do |addrinfo|
        yield addrinfo
      end
    end

    def self.build_udp(ip_address : IPAddress, family = Family::UNSPEC)
      build_addrinfo ip_address: ip_address, family: family, type: Type::DGRAM, protocol: Protocol::UDP do |addrinfo|
        yield addrinfo
      end
    end
  end
end
