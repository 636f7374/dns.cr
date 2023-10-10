struct DNS::Records
  struct MX < Records
    property name : String
    property classType : Packet::ClassFlag
    property ttl : Time::Span
    property mailExchange : String
    property preference : UInt16

    def initialize(@name : String, @classType : Packet::ClassFlag, @ttl : Time::Span, @mailExchange : String, @preference : UInt16)
    end

    def self.from_io(name : String, protocol_type : ProtocolType, io : IO, buffer : IO::Memory, options : Options = Options.new) : MX
      class_type = read_class_type! io: io
      ttl = read_ttl! io: io, buffer: buffer
      data_length = read_data_length! io: io
      preference = read_preference! io: io

      set_buffer! buffer: buffer, class_type: class_type, ttl: ttl, data_length: data_length, preference: preference
      mail_exchange = decode_name! protocol_type: protocol_type, io: io, buffer: buffer, options: options

      new name: name, classType: class_type, ttl: ttl.seconds, mailExchange: mail_exchange, preference: preference
    end

    private def self.read_preference!(io : IO) : UInt16
      begin
        io.read_bytes UInt16, IO::ByteFormat::BigEndian
      rescue ex
        raise Exception.new String.build { |io| io << "MX.read_preference!: Failed to read from IO, Because: (" << ex.message << ")." }
      end
    end

    private def self.set_buffer!(buffer : IO::Memory, class_type : Packet::ClassFlag, ttl : UInt32, data_length : UInt16, preference : UInt16)
      set_buffer! buffer: buffer, class_type: class_type, ttl: ttl, data_length: data_length

      begin
        buffer.write_bytes preference, IO::ByteFormat::BigEndian
      rescue ex
        raise Exception.new String.build { |io| io << "MX.set_buffer!: Writing to the buffer failed, Because: (" << ex.message << ")." }
      end
    end

    private def self.decode_name!(protocol_type : ProtocolType, io : IO, buffer : IO::Memory, options : Options = Options.new) : String
      begin
        Compress.decode protocol_type: protocol_type, io: io, buffer: buffer
      rescue ex
        raise Exception.new String.build { |io| io << "MX.decode_name!: Compress.decode! failed, Because: (" << ex.message << ")." }
      end
    end
  end
end
