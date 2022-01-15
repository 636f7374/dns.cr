abstract struct DNS::Address
  abstract def ipAddress : Socket::IPAddress
  abstract def timeout : TimeOut
  abstract def protocolType : DNS::ProtocolType
  abstract def create_socket!

  struct TransportLayerSecurity
    enum VerifyMode : UInt8
      NONE                 = 0_u8
      PEER                 = 1_u8
      FAIL_IF_NO_PEER_CERT = 2_u8
      CLIENT_ONCE          = 4_u8
    end

    property hostname : String?
    property options : Set(LibSSL::Options)
    property verifyMode : LibSSL::VerifyMode?

    def initialize(@hostname : String? = nil, @options : Set(LibSSL::Options) = Set(LibSSL::Options).new, @verifyMode : LibSSL::VerifyMode? = nil)
    end

    def unwrap : OpenSSL::SSL::Context::Client
      context = OpenSSL::SSL::Context::Client.new

      options.each { |option| context.add_options options: option }
      verifyMode.try { |verify_mode| context.verify_mode = verify_mode }

      context
    end
  end
end

require "./address/*"
