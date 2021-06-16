struct DNS::Records
  struct SRV < Records
    property name : String
    property classType : Packet::ClassFlag
    property ttl : Time::Span
    property priority : UInt16
    property weight : UInt16
    property port : UInt16
    property target : String

    def initialize(@name : String, @classType : Packet::ClassFlag, @ttl : Time::Span, @priority : UInt16, @weight : UInt16, @port : UInt16, @target : String)
    end

    def self.from_io(name : String, protocol_type : ProtocolType, io : IO, buffer : IO::Memory, options : Options = Options.new) : SRV
      class_type = read_class_type! io: io
      ttl = read_ttl! io: io, buffer: buffer
      data_length = read_data_length! io: io

      set_buffer! buffer: buffer, class_type: class_type, ttl: ttl, data_length: data_length
      data_length_buffer = read_data_length_buffer! io: io, buffer: buffer, length: data_length

      begin
        priority = data_length_buffer.read_bytes UInt16, IO::ByteFormat::BigEndian
        weight = data_length_buffer.read_bytes UInt16, IO::ByteFormat::BigEndian
        port = data_length_buffer.read_bytes UInt16, IO::ByteFormat::BigEndian
      rescue ex
        raise Exception.new String.build { |io| io << "SRV.from_io: Failed to read options Bytes from IO, Because: (" << ex.message << ")." }
      end

      target = decode_name! protocol_type: protocol_type, io: data_length_buffer, buffer: buffer, options: options
      new name: name, classType: class_type, ttl: ttl.seconds, priority: priority, weight: weight, port: port, target: target
    end

    private def self.read_data_length_buffer!(io : IO, buffer : IO, length : UInt16) : IO::Memory
      begin
        temporary = IO::Memory.new length
        copy_length = IO.copy io, temporary, length
        temporary.rewind
      rescue ex
        raise Exception.new String.build { |io| io << "SRV.read_data_length_buffer!: Because: (" << ex.message << ")." }
      end

      begin
        buffer.write temporary.to_slice
      rescue ex
        raise Exception.new String.build { |io| io << "SRV.read_data_length_buffer!: Writing to the buffer failed, Because: (" << ex.message << ")." }
      end

      temporary
    end

    private def self.decode_name!(protocol_type : ProtocolType, io : IO, buffer : IO::Memory, options : Options = Options.new) : String
      begin
        Compress.decode! protocol_type: protocol_type, io: io, buffer: buffer, options: options
      rescue ex
        raise Exception.new String.build { |io| io << "SRV.decode_name!: Compress.decode! failed, Because: (" << ex.message << ")." }
      end
    end
  end
end
