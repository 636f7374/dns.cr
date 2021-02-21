struct DNS::Records
  struct SOA < Records
    property name : String
    property classType : Packet::ClassFlag
    property ttl : Time::Span
    property primaryNameServer : String
    property authorityMailBox : String
    property serialNumber : UInt32
    property refreshInterval : UInt32
    property retryInterval : UInt32
    property expireLimit : UInt32
    property minimiumTimeToLive : UInt32

    def initialize(@name : String, @classType : Packet::ClassFlag, @ttl : Time::Span, @primaryNameServer : String, @authorityMailBox : String, @serialNumber : UInt32,
                   @refreshInterval : UInt32, @retryInterval : UInt32, @expireLimit : UInt32, @minimiumTimeToLive : UInt32)
    end

    def self.from_io(name : String, protocol_type : ProtocolType, io : IO, buffer : IO::Memory, maximum_depth : Int32 = 65_i32) : SOA
      class_type = read_class_type! io: io
      ttl = read_ttl! io: io, buffer: buffer
      data_length = read_data_length! io: io

      set_buffer! buffer: buffer, class_type: class_type, ttl: ttl, data_length: data_length
      name = "<Root>" if name.empty?
      data_length_buffer = read_data_length_buffer! io: io, buffer: buffer, length: data_length
      primary_name_server, authority_mail_box = decode_values! protocol_type: protocol_type, data_buffer: data_length_buffer, buffer: buffer, maximum_depth: maximum_depth

      begin
        serial_number = data_length_buffer.read_bytes UInt32, IO::ByteFormat::BigEndian
        refresh_interval = data_length_buffer.read_bytes UInt32, IO::ByteFormat::BigEndian
        retry_interval = data_length_buffer.read_bytes UInt32, IO::ByteFormat::BigEndian
        expire_limit = data_length_buffer.read_bytes UInt32, IO::ByteFormat::BigEndian
        minimium_time_to_live = data_length_buffer.read_bytes UInt32, IO::ByteFormat::BigEndian
      rescue ex
        raise Exception.new String.build { |io| io << "SOA.from_io: Failed to read options Bytes from IO, Because: (" << ex.message << ")." }
      end

      new name: name, classType: class_type, ttl: ttl.seconds, primaryNameServer: primary_name_server, authorityMailBox: authority_mail_box, serialNumber: serial_number,
        refreshInterval: refresh_interval, retryInterval: retry_interval, expireLimit: expire_limit, minimiumTimeToLive: minimium_time_to_live
    end

    private def self.read_data_length_buffer!(io : IO, buffer : IO, length : UInt16) : IO::Memory
      begin
        temporary = IO::Memory.new length
        copy_length = IO.copy io, temporary, length
        temporary.rewind
      rescue ex
        raise Exception.new String.build { |io| io << "SOA.read_data_length_buffer!: Because: (" << ex.message << ")." }
      end

      begin
        buffer.write temporary.to_slice
      rescue ex
        raise Exception.new String.build { |io| io << "SOA.read_data_length_buffer!: Writing to the buffer failed, Because: (" << ex.message << ")." }
      end

      temporary
    end

    private def self.decode_values!(protocol_type : ProtocolType, data_buffer : IO::Memory, buffer : IO::Memory, maximum_depth : Int32 = 65_i32) : Tuple(String, String)
      primary_name_server = decode_name! protocol_type: protocol_type, io: data_buffer, buffer: buffer, maximum_depth: maximum_depth
      authority_mail_box = decode_name! protocol_type: protocol_type, io: data_buffer, buffer: buffer, maximum_depth: maximum_depth
      Tuple.new primary_name_server, authority_mail_box
    end

    private def self.decode_name!(protocol_type : ProtocolType, io : IO, buffer : IO::Memory, maximum_depth : Int32 = 65_i32) : String
      begin
        Compress.decode! protocol_type: protocol_type, io: io, buffer: buffer, maximum_depth: maximum_depth
      rescue ex
        raise Exception.new String.build { |io| io << "SOA.decode_name!: Compress.decode! failed, Because: (" << ex.message << ")." }
      end
    end
  end
end
