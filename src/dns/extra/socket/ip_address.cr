class Socket
  struct IPAddress
    HYBRID_IPV6_PREFIX_BYTES = Bytes[0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 255_u8, 255_u8]

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

    def to_slice : Bytes
      case family
      in .inet?
        slice = Bytes.new size: 4_i32

        aton_uint32 = IPAddress.aton address: address
        IO::ByteFormat::BigEndian.encode int: aton_uint32, bytes: slice

        slice
      in .inet6?
        slice = Bytes.new size: 16_i32

        # Stripping "::ffff:" prefix from request.connection.remoteAddress nodejs: https://stackoverflow.com/questions/31100703/stripping-ffff-prefix-from-request-connection-remoteaddress-nodejs
        # What happens is your OS is listening with a hybrid IPv4-IPv6 socket, which converts any IPv4 address to IPv6, by embedding it within the IPv4-mapped IPv6 address format. This format just prefixes the IPv4 address with :ffff:, so you can recover the original IPv4 address by just stripping the :ffff:. (Some deprecated mappings prefix with :: instead of :ffff:, so we use the regex /^.*:/ to match both forms.)

        if address.starts_with?("::ffff:") && address.includes?('.')
          slice[0_u8, 12_u8].copy_from source: HYBRID_IPV6_PREFIX_BYTES
          Socket::IPAddress.new(address: address.rpartition("::ffff:").last, port: port).to_slice slice: slice[12_u8...], with_port: false

          return slice
        end

        # Default.

        pos = 0_u8

        IPAddress.ipv6_groups(address: address).each do |group|
          IO::ByteFormat::NetworkEndian.encode int: group.to_u16, bytes: slice[pos..(pos + 1_u8)]
          pos += 2_u8
        end

        slice
      in .unspec?
        raise Socket::Error.new String.build { |io| io << "IPAddress.to_slice: Unsupported Family Type (" << family << ")." }
      in .unix?
        raise Socket::Error.new String.build { |io| io << "IPAddress.to_slice: Unsupported Family Type (" << family << ")." }
      end
    end

    def to_slice(slice : Bytes, with_port : Bool = true) : Bytes
      case family
      in .inet?
        aton_uint32 = IPAddress.aton address: address
        IO::ByteFormat::BigEndian.encode int: aton_uint32, bytes: slice
        IO::ByteFormat::BigEndian.encode int: port.to_u16, bytes: slice[4_u8..5_u8] if with_port

        slice
      in .inet6?
        # Stripping "::ffff:" prefix from request.connection.remoteAddress nodejs: https://stackoverflow.com/questions/31100703/stripping-ffff-prefix-from-request-connection-remoteaddress-nodejs
        # What happens is your OS is listening with a hybrid IPv4-IPv6 socket, which converts any IPv4 address to IPv6, by embedding it within the IPv4-mapped IPv6 address format. This format just prefixes the IPv4 address with :ffff:, so you can recover the original IPv4 address by just stripping the :ffff:. (Some deprecated mappings prefix with :: instead of :ffff:, so we use the regex /^.*:/ to match both forms.)

        if address.starts_with?("::ffff:") && address.includes?('.')
          slice[0_u8, 12_u8].copy_from source: HYBRID_IPV6_PREFIX_BYTES
          Socket::IPAddress.new(address: address.rpartition("::ffff:").last, port: port).to_slice slice: slice[12_u8...], with_port: with_port

          return slice
        end

        # Default.

        pos = 0_u8

        IPAddress.ipv6_groups(address: address).each do |group|
          IO::ByteFormat::NetworkEndian.encode int: group.to_u16, bytes: slice[pos..(pos + 1_u8)]
          pos += 2_u8
        end

        IO::ByteFormat::BigEndian.encode int: port.to_u16, bytes: slice[16_u8..17_u8] if with_port
        slice
      in .unspec?
        raise Socket::Error.new String.build { |io| io << "IPAddress.to_slice: Unsupported Family Type (" << family << ")." }
      in .unix?
        raise Socket::Error.new String.build { |io| io << "IPAddress.to_slice: Unsupported Family Type (" << family << ")." }
      end
    end

    def self.parse(slice : Bytes, family : Family, with_port : Bool = false) : Socket::IPAddress
      case family
      in .inet?
        uint32 = IO::ByteFormat::BigEndian.decode int: UInt32, bytes: slice
        octets = [] of Int32

        4_i32.times do
          octets.unshift uint32.to_i! & 0xff
          uint32 >>= 8_i32
        end

        port = with_port ? IO::ByteFormat::BigEndian.decode(int: UInt16, bytes: slice[4_u8..5_u8]) : 0_u16
        new address: octets.join('.'), port: port
      in .inet6?
        # Stripping "::ffff:" prefix from request.connection.remoteAddress nodejs: https://stackoverflow.com/questions/31100703/stripping-ffff-prefix-from-request-connection-remoteaddress-nodejs
        # What happens is your OS is listening with a hybrid IPv4-IPv6 socket, which converts any IPv4 address to IPv6, by embedding it within the IPv4-mapped IPv6 address format. This format just prefixes the IPv4 address with :ffff:, so you can recover the original IPv4 address by just stripping the :ffff:. (Some deprecated mappings prefix with :: instead of :ffff:, so we use the regex /^.*:/ to match both forms.)

        if slice[0_u8, 12_u8] == HYBRID_IPV6_PREFIX_BYTES
          uint32 = IO::ByteFormat::BigEndian.decode int: UInt32, bytes: slice[12_u8...]
          octets = [] of Int32

          4_i32.times do
            octets.unshift uint32.to_i! & 0xff
            uint32 >>= 8_i32
          end

          port = with_port ? IO::ByteFormat::BigEndian.decode(int: UInt16, bytes: slice[16_u8..17_u8]) : 0_u16
          return new address: String.build { |io| io << "::ffff:" << octets.join('.') }, port: port
        end

        # Default.

        groups = [] of UInt16
        pos = 0_u8

        8_i32.times do
          groups << IO::ByteFormat::NetworkEndian.decode int: UInt16, bytes: slice[pos..(pos + 1_u8)]
          pos += 2_u8
        end

        port = with_port ? IO::ByteFormat::BigEndian.decode(int: UInt16, bytes: slice[16_u8..17_u8]) : 0_u16
        new address: (("%04x:" * 8_i32).rchop % groups), port: port
      in .unspec?
        raise Socket::Error.new String.build { |io| io << "IPAddress.from_io: Unsupported Family Type (" << family << ")." }
      in .unix?
        raise Socket::Error.new String.build { |io| io << "IPAddress.from_io: Unsupported Family Type (" << family << ")." }
      end
    end
  end
end
