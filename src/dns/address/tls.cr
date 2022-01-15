abstract struct DNS::Address
  struct TLS < Address
    property ipAddress : Socket::IPAddress
    property timeout : TimeOut
    property tls : TransportLayerSecurity?
    property protocolType : DNS::ProtocolType

    def initialize(@ipAddress : Socket::IPAddress, @timeout : TimeOut = TimeOut.new, @tls : TransportLayerSecurity? = nil)
      @protocolType = DNS::ProtocolType::TLS
    end

    def create_socket! : Tuple(OpenSSL::SSL::Context::Client?, OpenSSL::SSL::Socket::Client)
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
end
