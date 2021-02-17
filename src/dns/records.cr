abstract struct DNS::Records
  abstract def name : String

  private def self.read_class_type!(io : IO) : Packet::ClassFlag
    begin
      class_flag = io.read_bytes UInt16, IO::ByteFormat::BigEndian
    rescue ex
      raise Exception.new String.build { |io| io << "Records.read_class_type!: recordType and classType 4 Bytes, failed to read from IO!" }
    end

    begin
      class_type = Packet::ClassFlag.new class_flag
    rescue ex
      raise Exception.new String.build { |io| io << "Records.read_class_type!: It may be an incorrect Enum value, Because: (" << ex.message << ")." }
    end

    class_type
  end

  private def self.read_ttl!(io : IO, buffer : IO::Memory) : UInt32
    begin
      io.read_bytes UInt32, IO::ByteFormat::BigEndian
    rescue ex
      raise Exception.new String.build { |io| io << "Records.read_ttl!: recordType and classType 4 Bytes, failed to read from IO!" }
    end
  end

  private def self.read_data_length!(io : IO) : UInt16
    begin
      io.read_bytes UInt16, IO::ByteFormat::BigEndian
    rescue ex
      raise Exception.new String.build { |io| io << "Records.read_data_length!: Failed to read from IO, Because: (" << ex.message << ")." }
    end
  end

  private def self.set_buffer!(buffer : IO::Memory, class_type : Packet::ClassFlag, ttl : UInt32, data_length : UInt16)
    begin
      buffer.write_bytes class_type.value, IO::ByteFormat::BigEndian
      buffer.write_bytes ttl, IO::ByteFormat::BigEndian
      buffer.write_bytes data_length, IO::ByteFormat::BigEndian
    rescue ex
      raise Exception.new String.build { |io| io << "Records.set_buffer!: Writing to the buffer failed, Because: (" << ex.message << ")." }
    end
  end
end

require "./records/*"
