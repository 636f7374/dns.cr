struct DNS::Records
  struct TXT < Records
    property name : String
    property classType : Packet::ClassFlag
    property ttl : Time::Span
    property txt : String

    def initialize(@name : String, @classType : Packet::ClassFlag, @ttl : Time::Span, @txt : String)
    end

    def self.from_io(name : String, protocol_type : ProtocolType, io : IO, buffer : IO::Memory, maximum_depth : Int32 = 65_i32) : TXT
      class_type = read_class_type! io: io
      ttl = read_ttl! io: io, buffer: buffer
      data_length = read_data_length! io: io

      set_buffer! buffer: buffer, class_type: class_type, ttl: ttl, data_length: data_length
      data_length_buffer = read_data_length_buffer! io: io, buffer: buffer, length: data_length

      begin
        txt_length = data_length_buffer.read_byte
      rescue ex
        raise Exception.new String.build { |io| io << "TXT.from_io: Failed to read txt_length from IO, Because: (" << ex.message << ")." }
      end

      if txt_length != (data_length_buffer.size - 1_i32)
        raise Exception.new String.build { |io| io << "dataLength or TXTLength is incorrect, or Packet Error!" }
      end

      new name: name, classType: class_type, ttl: ttl.seconds, txt: data_length_buffer.gets_to_end
    end

    private def self.read_data_length_buffer!(io : IO, buffer : IO, length : UInt16) : IO::Memory
      begin
        temporary = IO::Memory.new length
        copy_length = IO.copy io, temporary, length
        buffer.write temporary.to_slice[0_i32, copy_length]
        temporary.rewind
      rescue ex
        raise Exception.new String.build { |io| io << "TXT.read_data_length_buffer!: Because: (" << ex.message << ")." }
      end

      temporary
    end
  end
end
