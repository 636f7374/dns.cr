module DNS::Sections
  struct Question
    property recordType : Packet::RecordFlag
    property name : String
    property classType : Packet::ClassFlag

    def initialize(@recordType : Packet::RecordFlag, @name : String, @classType : Packet::ClassFlag = Packet::ClassFlag::Internet)
    end

    def self.from_io(protocol_type : ProtocolType, io : IO, buffer : IO::Memory, maximum_depth : Int32 = 65_i32) : Question
      name = decode_name! protocol_type: protocol_type, io: io, buffer: buffer, maximum_depth: maximum_depth, add_length_offset: false
      record_type, class_type = read_types! io: io
      set_buffer! buffer: buffer, record_type: record_type, class_type: class_type
      question = new recordType: record_type, name: name, classType: class_type

      question
    end

    def to_io(io : IO) : IO
      Compress.encode_chunk_string io: io, value: name

      io.write_bytes recordType.value, IO::ByteFormat::BigEndian
      io.write_bytes classType.value, IO::ByteFormat::BigEndian

      io
    end

    private def self.decode_name!(protocol_type : ProtocolType, io : IO, buffer : IO::Memory, maximum_depth : Int32 = 65_i32, add_length_offset : Bool = false) : String
      begin
        Compress.decode! protocol_type: protocol_type, io: io, buffer: buffer, maximum_depth: maximum_depth, add_length_offset: add_length_offset
      rescue ex
        raise Exception.new String.build { |io| io << "Question.decode_name!: Compress.decode! failed, Because: (" << ex.message << ")." }
      end
    end

    private def self.read_types!(io : IO) : Tuple(Packet::RecordFlag, Packet::ClassFlag)
      begin
        record_flag = io.read_bytes UInt16, IO::ByteFormat::BigEndian
        class_flag = io.read_bytes UInt16, IO::ByteFormat::BigEndian
      rescue ex
        raise Exception.new String.build { |io| io << "Question.read_types!: recordType and classType 4 Bytes, failed to read from IO!" }
      end

      begin
        record_type = Packet::RecordFlag.new record_flag
        class_type = Packet::ClassFlag.new class_flag
      rescue ex
        raise Exception.new String.build { |io| io << "Question.read_types!: It may be an incorrect Enum value, Because: (" << ex.message << ")." }
      end

      Tuple.new record_type, class_type
    end

    private def self.set_buffer!(buffer : IO::Memory, record_type : Packet::RecordFlag, class_type : Packet::ClassFlag)
      begin
        buffer.write_bytes record_type.value, IO::ByteFormat::BigEndian
        buffer.write_bytes class_type.value, IO::ByteFormat::BigEndian
      rescue ex
        raise Exception.new String.build { |io| io << "Question.set_buffer!: Writing to the buffer failed, Because: (" << ex.message << ")." }
      end
    end
  end
end
