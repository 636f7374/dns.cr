struct DNS::Records
  struct TXT < Records
    property name : String
    property classType : Packet::ClassFlag
    property ttl : Time::Span
    property txt : String

    def initialize(@name : String, @classType : Packet::ClassFlag, @ttl : Time::Span, @txt : String)
      size = @txt.size
      if size > 255
        # Here, @txt includes an invalid character on the 255th byte (due to multiple packet concatenation--see below--so we manually remove.
        # Apologies on the code--rather iterate on groups of 256 bytes, dropping the last one, but didn't see how to crystal-lang that.
        buf = ""
        i = 0
        while i < size
          buf += @txt[i..i+254]
          i += 256
        end
        @txt = buf
      end
    end

    def self.from_io(name : String, protocol_type : ProtocolType, io : IO, buffer : IO::Memory, options : Options = Options.new) : TXT
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
        puts "Probably not an exception: txt_length=#{txt_length} but data_length_buffer=#{data_length_buffer.size-1_i32}"
        # raise Exception.new String.build { |io| io << "dataLength or TXTLength is incorrect, or Packet Error!" }
      end

      new name: name, classType: class_type, ttl: ttl.seconds, txt: data_length_buffer.gets_to_end
    end

    private def self.read_data_length_buffer!(io : IO, buffer : IO, length : UInt16) : IO::Memory
      begin
        temporary = IO::Memory.new length
        copy_length = IO.copy io, temporary, length
        temporary.rewind
      rescue ex
        raise Exception.new String.build { |io| io << "TXT.read_data_length_buffer!: Because: (" << ex.message << ")." }
      end

      begin
        buffer.write temporary.to_slice
      rescue ex
        raise Exception.new String.build { |io| io << "TXT.read_data_length_buffer!: Writing to the buffer failed, Because: (" << ex.message << ")." }
      end

      temporary
    end
  end
end
