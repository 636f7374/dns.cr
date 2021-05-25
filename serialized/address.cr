module DNS::Serialized
  struct Address
    include YAML::Serializable

    property ipAddress : String
    property protocolType : DNS::ProtocolType
    property timeout : TimeOut
    property tls : TransportLayerSecurity?

    def initialize(@ipAddress : String = "8.8.8.8:53", @protocolType : DNS::ProtocolType = DNS::ProtocolType::UDP, @timeout : TimeOut = TimeOut.new, @tls : TransportLayerSecurity? = nil)
    end

    def unwrap : DNS::Address?
      address, delimiter, port = ipAddress.rpartition ':'
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
end
