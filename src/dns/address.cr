struct DNS::Address
  property ipAddress : Socket::IPAddress
  property protocolType : ProtocolType
  property timeout : TimeOut
  property tls : TransportLayerSecurity?

  def initialize(@ipAddress : Socket::IPAddress, @protocolType : ProtocolType = ProtocolType::UDP, @timeout : TimeOut = TimeOut.new, @tls : TransportLayerSecurity? = nil)
  end

  def create_socket! : Tuple(OpenSSL::SSL::Context::Client?, UDPSocket | TCPSocket | OpenSSL::SSL::Socket::Client)
    case protocolType
    in .udp?
      socket = UDPSocket.new family: ipAddress.family
      socket.read_timeout = timeout.read
      socket.write_timeout = timeout.write
      socket.connect ip_address: ipAddress, connect_timeout: timeout.connect

      Tuple.new nil, socket
    in .tcp?
      socket = TCPSocket.new ip_address: ipAddress, connect_timeout: timeout.connect
      socket.read_timeout = timeout.read
      socket.write_timeout = timeout.write

      Tuple.new nil, socket
    in .tls?
      context = tls.try &.unwrap || OpenSSL::SSL::Context::Client.new

      socket = TCPSocket.new ip_address: ipAddress, connect_timeout: timeout.connect
      socket.read_timeout = timeout.read
      socket.write_timeout = timeout.write

      begin
        tls_socket = OpenSSL::SSL::Socket::Client.new socket, context: context, sync_close: true, hostname: tls.try &.hostname
        tls_socket.sync = true
      rescue ex
        socket.close rescue nil
        context.skip_finalize = true
        context.free

        raise ex
      end

      Tuple.new context, tls_socket
    end
  end

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
