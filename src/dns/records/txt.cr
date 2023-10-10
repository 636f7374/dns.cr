struct DNS::Records
  struct TXT < Records
    property name : String
    property classType : Packet::ClassFlag
    property ttl : Time::Span
    property txt : String

    def initialize(@name : String, @classType : Packet::ClassFlag, @ttl : Time::Span, @txt : String)
    end

    def self.from_io(name : String, protocol_type : ProtocolType, io : IO, buffer : IO::Memory, options : Options = Options.new) : TXT
      class_type = read_class_type! io: io
      ttl = read_ttl! io: io, buffer: buffer
      data_length_remaining = data_length = read_data_length! io: io
      set_buffer! buffer: buffer, class_type: class_type, ttl: ttl, data_length: data_length

      data_length_buffer = read_data_length_buffer! io: io, buffer: buffer, length: data_length
      data_buffer = IO::Memory.new

      until data_length_remaining.zero?
        txt_length = data_length_buffer.read_byte
        raise Exception.new String.build { |io| io << "TXT.from_io: Failed to read txt_length from IO." } unless txt_length
        raise Exception.new String.build { |io| io << "TXT.from_io: txt_length is Zero." } if txt_length.zero?
        data_length_remaining -= 1_u16

        data_buffer_gets = data_length_buffer.gets txt_length
        raise Exception.new String.build { |io| io << "TXT.from_io: Failed to read txt_length segment from IO." } unless data_buffer_gets

        data_buffer << data_buffer_gets
        data_length_remaining -= data_buffer_gets.size
      end

      data_buffer.rewind

      new name: name, classType: class_type, ttl: ttl.seconds, txt: data_buffer.gets_to_end
    end

    private def self.read_data_length_buffer!(io : IO, buffer : IO, length : UInt16) : IO::Memory
      begin
        bytes = Bytes.new size: length
        copy_length = io.read slice: bytes
      rescue ex
        raise Exception.new String.build { |io| io << "TXT.read_data_length_buffer!: Because: (" << ex.message << ")." }
      end

      begin
        buffer.write slice: bytes[0_i32, copy_length]
      rescue ex
        raise Exception.new String.build { |io| io << "TXT.read_data_length_buffer!: Writing to the buffer failed, Because: (" << ex.message << ")." }
      end

      IO::Memory.new bytes[0_i32, copy_length]
    end
  end
end
