struct DNS::Options
  property socket : Socket
  property addrinfo : Addrinfo

  def initialize(@socket : Socket = Socket.new, @addrinfo : Addrinfo = Addrinfo.new)
  end

  struct Socket
    property ipv4ConnectionFailureRetryTimes : Int32
    property ipv6ConnectionFailureRetryTimes : Int32

    def initialize
      @ipv4ConnectionFailureRetryTimes = 2_i32
      @ipv6ConnectionFailureRetryTimes = 2_i32
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
    property queryIpv6 : Bool
    property filterType : FilterType
    property maximumCanonicalNameDepth : Int32

    def initialize
      @answerSafetyFirst = true
      @maximumNumberOfMismatchRetries = 3_i32
      @enableProtection = true
      @protectionWaitingTime = 5_i32.seconds
      @concurrentQuery = true
      @queryIpv6 = false
      @filterType = FilterType::Ipv4Only
      @maximumCanonicalNameDepth = 64_i32
    end
  end
end
