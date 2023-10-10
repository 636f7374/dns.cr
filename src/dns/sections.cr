module DNS::Sections
  {% for section in ["additional", "answer", "authority"] %}
  struct {{section.capitalize.id}}
    def self.from_io(protocol_type : ProtocolType, io : IO, buffer : IO::Memory, options : Options = Options.new) : Records
      name = decode_name! protocol_type: protocol_type, io: io, buffer: buffer, options: options
      record_type = read_record_type! io: io
      set_buffer! buffer: buffer, record_type: record_type

      {% begin %}
      case record_type
        {% for available_type in AvailableRecordFlags %}
      when .{{available_type.downcase.id}}?
        Records::{{available_type.id}}.from_io name: name, protocol_type: protocol_type, io: io, buffer: buffer, options: options
        {% end %}
      else
        raise Exception.new String.build { |io| io << {{section.capitalize.id.stringify}} << ".from_io: Unfortunately, decoded to an unsupported recordType, currently DNS.cr cannot handle this recordType (" << record_type << ")." }
      end
      {% end %}
    end

    private def self.decode_name!(protocol_type : ProtocolType, io : IO, buffer : IO::Memory, options : Options = Options.new) : String
      begin
        Compress.decode protocol_type: protocol_type, io: io, buffer: buffer
      rescue ex
        raise Exception.new String.build { |io| io << {{section.capitalize.id.stringify}} << ".decode_name!: Compress.decode_by_pointer! failed, Because: (" << ex.message << ")." }
      end
    end

    private def self.read_record_type!(io : IO) : Packet::RecordFlag
      begin
        record_flag = io.read_bytes UInt16, IO::ByteFormat::BigEndian
      rescue ex
        raise Exception.new String.build { |io| io << {{section.capitalize.id.stringify}} << ".read_record_type!: recordType is 2 Bytes, failed to read from IO!" }
      end

      begin
        record_type = Packet::RecordFlag.new record_flag
      rescue ex
        raise Exception.new String.build { |io| io << {{section.capitalize.id.stringify}} << ".read_record_type!: It may be an incorrect Enum value, Because: (" << ex.message << ")." }
      end

      record_type
    end

    private def self.set_buffer!(buffer : IO::Memory, record_type : Packet::RecordFlag)
      begin
        buffer.write_bytes record_type.value, IO::ByteFormat::BigEndian
      rescue ex
        raise Exception.new String.build { |io| io << {{section.capitalize.id.stringify}} << ".set_buffer!: Writing to the buffer failed, Because: (" << ex.message << ")." }
      end
    end
  end
  {% end %}
end

require "./sections/*"
