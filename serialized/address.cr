module DNS::Serialized
  abstract struct Address
    include YAML::Serializable

    getter protocolType : String

    abstract def ipAddress : String
    abstract def timeout : TimeOut
    abstract def unwrap : DNS::Address?

    use_yaml_discriminator "protocolType", {
      "udp"   => UDP,
      "tcp"   => TCP,
      "tls"   => TLS,
      "http"  => HTTP,
      "https" => HTTPS,
    }

    def self.unwrap_ip_address(ip_address : String) : Socket::IPAddress?
      address, delimiter, port = ip_address.rpartition ':'
      return unless _port = port.to_i?
      address = address.gsub /[\[\]]+/, nil

      Socket::IPAddress.new address: address, port: _port rescue nil
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

require "./address/*"
