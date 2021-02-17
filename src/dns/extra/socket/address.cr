class Socket
  abstract struct Address
    # Convert IP address in sockaddr to uint32_t | https://stackoverflow.com/questions/32845445/convert-ip-address-in-sockaddr-to-uint32-t

    def self.ipv4_from_io(io : IO, addrlen : Int = 4_i32) : Address
      sockaddrin = LibC::SockaddrIn.new
      sockaddrin.sin_addr.s_addr = io.read_bytes UInt32, IO::ByteFormat::LittleEndian
      sockaddrin.sin_family = LibC::AF_INET
      sockaddrin.sin_port = 0_i32

      sockaddr = pointerof(sockaddrin).as LibC::Sockaddr*
      from sockaddr, addrlen
    end

    # Why is sin6_family needed on an IPv6 address? | https://stackoverflow.com/questions/26766002/why-is-sin6-family-needed-on-an-ipv6-address
    # What is the purpose of the sa_data field in a sockaddr? | https://stackoverflow.com/questions/32624847/what-is-the-purpose-of-the-sa-data-field-in-a-sockaddr
    # Github musllvm/include/netinet/in.h | https://github.com/SRI-CSL/musllvm/blob/master/include/netinet/in.h

    def self.ipv6_from_io(io : IO, addrlen : Int = 16_i32) : Address
      sockaddrin6_buffer = uninitialized UInt8[16_i32]
      length = io.read sockaddrin6_buffer.to_slice

      if 16_i32 != length
        raise Exception.new "Ipv6 address length cannot be less than 16 Bytes"
      end

      sockaddrin6 = LibC::SockaddrIn6.new
      sockaddrin6.sin6_family = LibC::AF_INET6
      sockaddrin6.sin6_port = 0_i32

      {% if flag?(:darwin) || flag?(:openbsd) || flag?(:freebsd) %}
        u6_addr = sockaddrin6.sin6_addr.__u6_addr

        sockaddrin6_buffer.each_with_index do |byte, index|
          u6_addr.__u6_addr8.to_slice[index] = byte
        end

        sockaddrin6.sin6_addr.__u6_addr = u6_addr
      {% elsif flag?(:linux) && flag?(:musl) %}
        u6_addr = sockaddrin6.sin6_addr.__in6_union

        sockaddrin6_buffer.each_with_index do |byte, index|
          u6_addr.__s6_addr.to_slice[index] = byte
        end

        sockaddrin6.sin6_addr.__in6_union = u6_addr
      {% elsif flag?(:linux) %}
        u6_addr = sockaddrin6.sin6_addr.__in6_u

        sockaddrin6_buffer.each_with_index do |byte, index|
          u6_addr.__u6_addr8.to_slice[index] = byte
        end

        sockaddrin6.sin6_addr.__in6_u = u6_addr
      {% else %}
        raise Exception.new "Unsupported platforms Address.ipv6_from_io"
      {% end %}

      sockaddr = pointerof(sockaddrin6).as LibC::Sockaddr*
      from sockaddr, addrlen
    end

    def self.ipv4_to_bytes(ip_address : Address) : Bytes?
      return unless ip_address.family.inet?
      ipv4_to_bytes! ip_address rescue nil
    end

    def self.ipv4_to_bytes!(ip_address : Address) : Bytes
      raise Exception.new "Address.ipv4_to_bytes!: IP address family is not INET!" unless ip_address.family.inet?

      pointer = ip_address.to_unsafe.as LibC::SockaddrIn*
      memory = IO::Memory.new 4_i32

      s_addr = pointer.value.sin_addr.s_addr
      memory.write_bytes s_addr, IO::ByteFormat::LittleEndian

      memory.to_slice
    end

    def self.ipv6_to_bytes(ip_address : Address) : Bytes?
      return unless ip_address.family.inet6?
      ipv6_to_bytes! ip_address rescue nil
    end

    def self.ipv6_to_bytes!(ip_address : Address) : Bytes
      raise Exception.new "Address.ipv6_to_bytes!: IP address family is not INET6!" unless ip_address.family.inet6?

      pointer = ip_address.to_unsafe.as LibC::SockaddrIn6*
      memory = IO::Memory.new 16_i32

      {% if flag?(:darwin) || flag?(:openbsd) || flag?(:freebsd) %}
        ipv6_address = pointer.value.sin6_addr.__u6_addr.__u6_addr8
        memory.write ipv6_address.to_slice
      {% elsif flag?(:linux) && flag?(:musl) %}
        ipv6_address = pointer.value.sin6_addr.__in6_union.__s6_addr
        memory.write ipv6_address.to_slice
      {% elsif flag?(:linux) %}
        ipv6_address = pointer.value.sin6_addr.__in6_u.__u6_addr8
        memory.write ipv6_address.to_slice
      {% else %}
        raise Exception.new "Unsupported platforms Address.ipv6_to_bytes!"
      {% end %}

      memory.to_slice
    end
  end
end
