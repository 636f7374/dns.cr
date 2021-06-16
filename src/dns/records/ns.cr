struct DNS::Records
  struct NS < Records
    property name : String
    property classType : Packet::ClassFlag
    property ttl : Time::Span
    property nameServer : String

    def initialize(@name : String, @classType : Packet::ClassFlag, @ttl : Time::Span, @nameServer : String)
    end

    def self.from_io(name : String, protocol_type : ProtocolType, io : IO, buffer : IO::Memory, options : Options = Options.new, maximum_length : UInt16 = 512_u16) : NS
      class_type = read_class_type! io: io
      ttl = read_ttl! io: io, buffer: buffer
      data_length = read_data_length! io: io

      set_buffer! buffer: buffer, class_type: class_type, ttl: ttl, data_length: data_length
      name_server = Compress.decode_by_length! protocol_type: protocol_type, io: io, length: data_length, buffer: buffer, options: options, maximum_length: maximum_length

      new name: name, classType: class_type, ttl: ttl.seconds, nameServer: name_server
    end
  end
end
