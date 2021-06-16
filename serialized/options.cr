module DNS::Serialized
  abstract struct Options
    struct Standard < Options
      include YAML::Serializable

      property socket : Socket
      property addrinfo : Addrinfo
      property packet : Packet

      def initialize(@socket : Socket = Socket.new, @addrinfo : Addrinfo = Addrinfo.new, @packet : Packet = Packet.new)
      end

      def unwrap : DNS::Options
        DNS::Options.new socket: socket.unwrap, addrinfo: addrinfo.unwrap, packet: packet.unwrap
      end

      struct Socket
        include YAML::Serializable

        property maximumNumberOfRetriesForPerIpAddress : UInt8
        property maximumNumberOfRetriesForIpv4ConnectionFailure : UInt8
        property maximumNumberOfRetriesForIpv6ConnectionFailure : UInt8

        def initialize
          @maximumNumberOfRetriesForPerIpAddress = 1_u8
          @maximumNumberOfRetriesForIpv4ConnectionFailure = 2_u8
          @maximumNumberOfRetriesForIpv6ConnectionFailure = 2_u8
        end

        def unwrap : DNS::Options::Socket
          socket = DNS::Options::Socket.new

          socket.maximumNumberOfRetriesForPerIpAddress = maximumNumberOfRetriesForPerIpAddress
          socket.maximumNumberOfRetriesForIpv4ConnectionFailure = maximumNumberOfRetriesForIpv4ConnectionFailure
          socket.maximumNumberOfRetriesForIpv6ConnectionFailure = maximumNumberOfRetriesForIpv6ConnectionFailure

          socket
        end
      end

      struct Addrinfo
        include YAML::Serializable

        property answerSafetyFirst : Bool
        property maximumNumberOfMismatchRetries : Int32
        property enableProtection : Bool
        property protectionWaitingTime : UInt8
        property concurrentQuery : Bool
        property queryType : DNS::Options::Addrinfo::FilterType
        property filterType : DNS::Options::Addrinfo::FilterType

        def initialize
          @answerSafetyFirst = true
          @maximumNumberOfMismatchRetries = 3_i32
          @enableProtection = true
          @protectionWaitingTime = 5_u8
          @concurrentQuery = true
          @queryType = DNS::Options::Addrinfo::FilterType::Ipv4Only
          @filterType = DNS::Options::Addrinfo::FilterType::Ipv4Only
        end

        def unwrap : DNS::Options::Addrinfo
          addrinfo = DNS::Options::Addrinfo.new

          addrinfo.answerSafetyFirst = answerSafetyFirst
          addrinfo.maximumNumberOfMismatchRetries = maximumNumberOfMismatchRetries
          addrinfo.enableProtection = enableProtection
          addrinfo.protectionWaitingTime = protectionWaitingTime.seconds
          addrinfo.concurrentQuery = concurrentQuery
          addrinfo.queryType = queryType
          addrinfo.filterType = filterType

          addrinfo
        end
      end

      struct Packet
        include YAML::Serializable

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

        def unwrap : DNS::Options::Packet
          packet = DNS::Options::Packet.new

          packet.maximumCountOfQuestion = maximumCountOfQuestion
          packet.maximumCountOfAnswer = maximumCountOfAnswer
          packet.maximumCountOfAuthority = maximumCountOfAuthority
          packet.maximumCountOfAdditional = maximumCountOfAdditional
          packet.maximumDepthOfCanonicalName = maximumDepthOfCanonicalName
          packet.maximumSizeOfPerChunk = maximumSizeOfPerChunk
          packet.maximumSizeOfPacket = maximumSizeOfPacket

          packet
        end
      end
    end
  end
end
