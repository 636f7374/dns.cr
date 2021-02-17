struct DNS::Records
  struct A < Records
    property name : String
    property classType : Packet::ClassFlag
    property ttl : Time::Span
    property address : Socket::IPAddress

    def initialize(@name : String, @classType : Packet::ClassFlag, @ttl : Time::Span, @address : Socket::IPAddress)
    end

    def self.from_io(name : String, protocol_type : ProtocolType, io : IO, buffer : IO::Memory, maximum_depth : Int32 = 65_i32, maximum_length : UInt16 = 512_u16) : A
      class_type = read_class_type! io: io
      ttl = read_ttl! io: io, buffer: buffer
      data_length = read_data_length! io: io

      set_buffer! buffer: buffer, class_type: class_type, ttl: ttl, data_length: data_length
      address = read_ipv4_address! io: io, buffer: buffer, length: data_length

      new name: name, classType: class_type, ttl: ttl.seconds, address: address
    end

    private def self.read_ipv4_address!(io : IO, buffer : IO, length : UInt16) : Socket::IPAddress
      raise Exception.new String.build { |io| io << "A.read_ipv4_address!: Ipv4 address length cannot be greater than 4, or data packet error!" } if length != 4_u16

      begin
        temporary = IO::Memory.new length
        copy_length = IO.copy io, temporary, length
        buffer.write temporary.to_slice[0_i32, copy_length]
        temporary.rewind

        Socket::IPAddress.ipv4_from_io io: temporary, addrlen: length
      rescue ex
        raise Exception.new String.build { |io| io << "A.read_ipv4_address!: Because: (" << ex.message << ")." }
      end
    end
  end
end
