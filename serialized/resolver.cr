module DNS::Serialized
  struct Resolver
    include YAML::Serializable

    property servers : Array(Address)
    property caching : Caching
    property options : Options

    def initialize(@servers : Array(Address) = [Address.new] of Address, @caching : Caching = Caching.new, @options : Options = Options.new)
    end

    def unwrap : DNS::Resolver
      DNS::Resolver.new dnsServers: unwrap_servers, options: unwrap_options, ipAddressCaching: caching.ipAddress.unwrap, packetCaching: caching.packet.unwrap, mapperCaching: caching.mapper.unwrap
    end

    def unwrap_servers : Set(DNS::Address)
      list = Set(DNS::Address).new

      servers.each do |server|
        next unless address = server.unwrap
        list << address
      end

      list
    end

    def unwrap_caching_packet : DNS::Caching::Packet
      caching.packet.unwrap
    end

    def unwrap_caching_ip_address : DNS::Caching::IPAddress
      caching.ipAddress.unwrap
    end

    def unwrap_caching_mapper : DNS::Caching::IPAddress
      caching.mapper.unwrap
    end

    def unwrap_options : DNS::Options
      options.unwrap
    end

    struct Address
      include YAML::Serializable

      property ipAddress : String
      property protocolType : DNS::ProtocolType
      property timeout : TimeOut
      property tls : TransportLayerSecurity?

      def initialize(@ipAddress : String = "8.8.8.8:53", @protocolType : DNS::ProtocolType = DNS::ProtocolType::UDP, @timeout : TimeOut = TimeOut.new, @tls : TransportLayerSecurity? = nil)
      end

      def unwrap : DNS::Address?
        address, delimiter, port = ipAddress.rpartition ":"
        return unless _port = port.to_i?
        ip_address = Socket::IPAddress.new address: address, port: _port rescue nil
        return unless ip_address

        DNS::Address.new ipAddress: ip_address, protocolType: protocolType, timeout: timeout.unwrap, tls: tls.try &.unwrap
      end

      struct TransportLayerSecurity
        include YAML::Serializable

        property hostname : String?
        property options : Array(String)
        property verifyMode : DNS::Address::TransportLayerSecurity::VerifyMode?

        def initialize(@hostname : String? = nil, @options : Array(String) = [] of String, @verifyMode : DNS::Address::TransportLayerSecurity::VerifyMode? = nil)
        end

        def unwrap_options : Set(LibSSL::Options)
          options_set = Set(LibSSL::Options).new

          options.each do |option|
            next unless _option = OpenSSL::SSL::Options.parse? option
            options_set << _option
          end

          options_set
        end

        def unwrap_verify_mode : LibSSL::VerifyMode?
          verify_mode = nil
          verifyMode.try { |_verify_mode| verify_mode = LibSSL::VerifyMode.new _verify_mode.value.to_i32 }
          verify_mode
        end

        def unwrap : DNS::Address::TransportLayerSecurity
          DNS::Address::TransportLayerSecurity.new hostname: hostname, options: unwrap_options, verifyMode: unwrap_verify_mode
        end
      end
    end

    struct Caching
      include YAML::Serializable

      property ipAddress : IpAddress
      property packet : Packet
      property mapper : Mapper

      def initialize(@ipAddress : IpAddress, @packet : Packet, @mapper : Mapper)
      end

      {% for type in ["ip_address", "packet", "mapper"] %}
      struct {{type.camelcase.id}}
        include YAML::Serializable

        property capacity : Int32
        property clearInterval : Int32
        property numberOfEntriesCleared : Int32

        def initialize(@capacity : Int32 = 512_i32, @clearInterval : Int32 = 3600_i32, @numberOfEntriesCleared : Int32 = 256_i32)
        end

        def unwrap
          {% if type == "packet" %}
            DNS::Caching::Packet.new capacity: capacity, clearInterval: clearInterval.seconds, numberOfEntriesCleared: numberOfEntriesCleared
          {% else %}
            DNS::Caching::IPAddress.new capacity: capacity, clearInterval: clearInterval.seconds, numberOfEntriesCleared: numberOfEntriesCleared
          {% end %}
        end
      end
      {% end %}
    end

    struct Options
      include YAML::Serializable

      property socket : Socket
      property addrinfo : Addrinfo

      def initialize(@socket : Socket = Socket.new, @addrinfo : Addrinfo = Addrinfo.new)
      end

      def unwrap : DNS::Options
        DNS::Options.new socket: socket.unwrap, addrinfo: addrinfo.unwrap
      end

      struct Socket
        include YAML::Serializable

        property maximumTimesOfIpv4ConnectionFailureRetries : Int32
        property maximumTimesOfIpv6ConnectionFailureRetries : Int32

        def initialize
          @maximumTimesOfIpv4ConnectionFailureRetries = 2_i32
          @maximumTimesOfIpv6ConnectionFailureRetries = 2_i32
        end

        def unwrap : DNS::Options::Socket
          socket = DNS::Options::Socket.new

          socket.maximumTimesOfIpv4ConnectionFailureRetries = maximumTimesOfIpv4ConnectionFailureRetries
          socket.maximumTimesOfIpv6ConnectionFailureRetries = maximumTimesOfIpv6ConnectionFailureRetries

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
        property maximumDepthOfCanonicalName : Int32

        def initialize
          @answerSafetyFirst = true
          @maximumNumberOfMismatchRetries = 3_i32
          @enableProtection = true
          @protectionWaitingTime = 5_u8
          @concurrentQuery = true
          @queryType = DNS::Options::Addrinfo::FilterType::Ipv4Only
          @filterType = DNS::Options::Addrinfo::FilterType::Ipv4Only
          @maximumDepthOfCanonicalName = 64_i32
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
          addrinfo.maximumDepthOfCanonicalName = maximumDepthOfCanonicalName

          addrinfo
        end
      end
    end

    struct TimeOut
      include YAML::Serializable

      property read : Int32
      property write : Int32
      property connect : Int32

      def initialize
        @read = 2_i32
        @write = 2_i32
        @connect = 2_i32
      end

      def unwrap : DNS::TimeOut
        timeout = DNS::TimeOut.new

        timeout.read = read
        timeout.write = write
        timeout.connect = connect

        timeout
      end
    end
  end
end
