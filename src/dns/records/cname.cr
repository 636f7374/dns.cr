struct DNS::Records
  struct CNAME < Records
    property name : String
    property classType : Packet::ClassFlag
    property ttl : Time::Span
    property canonicalName : String

    def initialize(@name : String, @classType : Packet::ClassFlag, @ttl : Time::Span, @canonicalName : String)
    end

    def self.from_io(name : String, protocol_type : ProtocolType, io : IO, buffer : IO::Memory, options : Options = Options.new, maximum_length : UInt16 = 512_u16) : CNAME
      class_type = read_class_type! io: io
      ttl = read_ttl! io: io, buffer: buffer
      data_length = read_data_length! io: io

      set_buffer! buffer: buffer, class_type: class_type, ttl: ttl, data_length: data_length
      canonical_name = Compress.decode protocol_type: protocol_type, io: io, buffer: buffer

      new name: name, classType: class_type, ttl: ttl.seconds, canonicalName: canonical_name
    end
  end
end
