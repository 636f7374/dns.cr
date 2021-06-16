struct DNS::Records
  struct OPT < Records
    property name : String
    property udpPayloadSize : UInt16
    property higherBitsExtendedRcode : UInt8
    property edns0Version : UInt8
    property z : UInt16

    def initialize(@name : String, @udpPayloadSize : UInt16, @higherBitsExtendedRcode : UInt8, @edns0Version : UInt8, @z : UInt16)
    end

    def self.from_io(name : String, protocol_type : ProtocolType, io : IO, buffer : IO::Memory, options : Options = Options.new, maximum_length : UInt16 = 512_u16) : OPT
      udp_payload_size = read_udp_payload_size! io: io
      higher_bits_extended_rcode = read_higher_bits_extended_rcode! io: io
      edns0_version = read_edns0_version! io: io
      z = read_z! io: io
      data_length = read_data_length! io: io

      set_buffer! buffer: buffer, udp_payload_size: udp_payload_size, higher_bits_extended_rcode: higher_bits_extended_rcode, edns0_version: edns0_version, z: z, data_length: data_length
      name = "<Root>" if name.empty?
      new name: name, udpPayloadSize: udp_payload_size, higherBitsExtendedRcode: higher_bits_extended_rcode, edns0Version: edns0_version, z: z
    end

    private def self.read_udp_payload_size!(io : IO) : UInt16
      begin
        io.read_bytes UInt16, IO::ByteFormat::BigEndian
      rescue ex
        raise Exception.new String.build { |io| io << "OPT.read_udp_payload_size!: Failed to read from IO, Because: (" << ex.message << ")." }
      end
    end

    private def self.read_higher_bits_extended_rcode!(io : IO) : UInt8
      begin
        io.read_bytes UInt8, IO::ByteFormat::BigEndian
      rescue ex
        raise Exception.new String.build { |io| io << "OPT.read_higher_bits_extended_rcode!: Failed to read from IO, Because: (" << ex.message << ")." }
      end
    end

    private def self.read_edns0_version!(io : IO) : UInt8
      begin
        io.read_bytes UInt8, IO::ByteFormat::BigEndian
      rescue ex
        raise Exception.new String.build { |io| io << "OPT.read_edns0_version!: Failed to read from IO, Because: (" << ex.message << ")." }
      end
    end

    private def self.read_z!(io : IO) : UInt16
      begin
        io.read_bytes UInt16, IO::ByteFormat::BigEndian
      rescue ex
        raise Exception.new String.build { |io| io << "OPT.read_z!: Failed to read from IO, Because: (" << ex.message << ")." }
      end
    end

    private def self.set_buffer!(buffer : IO::Memory, udp_payload_size : UInt16, higher_bits_extended_rcode : UInt8, edns0_version : UInt8, z : UInt16, data_length : UInt16)
      begin
        buffer.write_bytes udp_payload_size, IO::ByteFormat::BigEndian
        buffer.write_bytes higher_bits_extended_rcode, IO::ByteFormat::BigEndian
        buffer.write_bytes edns0_version, IO::ByteFormat::BigEndian
        buffer.write_bytes z, IO::ByteFormat::BigEndian
        buffer.write_bytes data_length, IO::ByteFormat::BigEndian
      rescue ex
        raise Exception.new String.build { |io| io << "OPT.set_buffer!: Writing to the buffer failed, Because: (" << ex.message << ")." }
      end
    end
  end
end
