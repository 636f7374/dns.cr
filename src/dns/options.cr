struct DNS::Options
  property socket : Socket
  property addrinfo : Addrinfo

  def initialize(@socket : Socket = Socket.new, @addrinfo : Addrinfo = Addrinfo.new)
  end

  struct Socket
    property maximumTimesOfIpv4ConnectionFailureRetries : Int32
    property maximumTimesOfIpv6ConnectionFailureRetries : Int32

    def initialize
      @maximumTimesOfIpv4ConnectionFailureRetries = 2_i32
      @maximumTimesOfIpv6ConnectionFailureRetries = 2_i32
    end
  end

  struct Addrinfo
    enum FilterType : UInt8
      Ipv4Only = 0_u8
      Ipv6Only = 1_u8
      Both     = 2_u8
    end

    property answerSafetyFirst : Bool
    property maximumNumberOfMismatchRetries : Int32
    property enableProtection : Bool
    property protectionWaitingTime : Time::Span
    property concurrentQuery : Bool
    property queryType : FilterType
    property filterType : FilterType
    property maximumDepthOfCanonicalName : Int32

    def initialize
      @answerSafetyFirst = true
      @maximumNumberOfMismatchRetries = 3_i32
      @enableProtection = true
      @protectionWaitingTime = 5_i32.seconds
      @concurrentQuery = true
      @queryType = FilterType::Ipv4Only
      @filterType = FilterType::Ipv4Only
      @maximumDepthOfCanonicalName = 64_i32
    end
  end
end
