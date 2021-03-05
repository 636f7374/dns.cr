class Socket
  struct IPAddress
    def self.ipv6_groups(address : String) : Array(Int32)
      matched = address.match /^(.*)::(.*)$/

      if matched
        left, right = [matched[1_i32], matched[2_i32]].map &.split(':')
      else
        left, right = address.split(':'), [] of String
      end

      Tuple.new(left, right).each &.reject! &.empty?
      groups = left + Array.new(8_i32 - left.size - right.size, '0') + right
      groups.map &.to_i 16_i32
    end

    def self.aton(address : String) : UInt32
      # Array formed with the IP octets
      octets = address.split('.').map &.to_u32

      # 32 bits integer containing the address
      (octets[0_i32] << 24_i32) + (octets[1_i32] << 16_i32) + (octets[2_i32] << 8_i32) + (octets[3_i32])
    end

    def to_slice
      memory = IO::Memory.new

      case family
      in .inet?
        aton_uint32 = IPAddress.aton address
        memory.write_bytes aton_uint32, IO::ByteFormat::BigEndian

        memory.to_slice
      in .inet6?
        IPAddress.ipv6_groups(address).each { |group| memory.write_bytes group.to_u16, IO::ByteFormat::NetworkEndian }
      in .unspec?
        raise Socket::Error.new String.build { |io| io << "IPAddress.to_slice: Unsupported Family Type (" << family << ")." }
      in .unix?
        raise Socket::Error.new String.build { |io| io << "IPAddress.to_slice: Unsupported Family Type (" << family << ")." }
      end

      memory.to_slice
    end

    def self.from_io(io : IO, family : Family)
      case family
      in .inet?
        uint32 = io.read_bytes UInt32, IO::ByteFormat::BigEndian
        octets = [] of Int32

        4_i32.times do
          octets.unshift uint32.to_i! & 0xff
          uint32 >>= 8_i32
        end

        new address: octets.join('.'), port: 0_i32
      in .inet6?
        groups = [] of UInt16

        8_i32.times do
          groups << io.read_bytes UInt16, IO::ByteFormat::NetworkEndian
        end

        new address: (("%04x:" * 8_i32).rchop % groups), port: 0_i32
      in .unspec?
        raise Socket::Error.new String.build { |io| io << "IPAddress.from_io: Unsupported Family Type (" << family << ")." }
      in .unix?
        raise Socket::Error.new String.build { |io| io << "IPAddress.from_io: Unsupported Family Type (" << family << ")." }
      end
    end
  end
end
