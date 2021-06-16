struct DNS::Options
  property socket : Socket
  property addrinfo : Addrinfo
  property packet : Packet

  def initialize(@socket : Socket = Socket.new, @addrinfo : Addrinfo = Addrinfo.new, @packet : Packet = Packet.new)
  end

  struct Socket
    property maximumNumberOfRetriesForPerIpAddress : UInt8
    property maximumNumberOfRetriesForIpv4ConnectionFailure : UInt8
    property maximumNumberOfRetriesForIpv6ConnectionFailure : UInt8

    def initialize
      @maximumNumberOfRetriesForPerIpAddress = 1_u8
      @maximumNumberOfRetriesForIpv4ConnectionFailure = 2_u8
      @maximumNumberOfRetriesForIpv6ConnectionFailure = 2_u8
    end
  end

  struct Addrinfo
    enum FilterType : UInt8
      Ipv4Only = 0_u8
      Ipv6Only = 1_u8
      Both     = 2_u8
    end

    property answerStrictlySafe : Bool
    property answerSafetyFirst : Bool
    property maximumNumberOfMismatchRetries : Int32
    property enableProtection : Bool
    property protectionWaitingTime : Time::Span
    property concurrentQuery : Bool
    property queryType : FilterType
    property filterType : FilterType

    def initialize
      @answerStrictlySafe = true
      @answerSafetyFirst = true
      @maximumNumberOfMismatchRetries = 3_i32
      @enableProtection = true
      @protectionWaitingTime = 5_i32.seconds
      @concurrentQuery = true
      @queryType = FilterType::Ipv4Only
      @filterType = FilterType::Ipv4Only
    end
  end

  struct Packet
    property maximumCountOfQuestion : UInt16
    property maximumCountOfAnswer : UInt16
    property maximumCountOfAuthority : UInt16
    property maximumCountOfAdditional : UInt16
    property maximumDepthOfCanonicalName : UInt8
    property maximumSizeOfPerChunk : UInt16
    property maximumSizeOfPacket : UInt16

    def initialize
      @maximumCountOfQuestion = 128_u16
      @maximumCountOfAnswer = 128_u16
      @maximumCountOfAuthority = 128_u16
      @maximumCountOfAdditional = 128_u16
      @maximumDepthOfCanonicalName = 64_u8
      @maximumSizeOfPerChunk = 2048_u16
      @maximumSizeOfPacket = 65535_u16
    end
  end
end
