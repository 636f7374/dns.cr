abstract struct DNS::Address
  struct TLS < Address
    property ipAddress : Socket::IPAddress
    property timeout : TimeOut
    property tls : TransportLayerSecurity?
    property protocolType : DNS::ProtocolType

    def initialize(@ipAddress : Socket::IPAddress, @timeout : TimeOut = TimeOut.new, @tls : TransportLayerSecurity? = nil)
      @protocolType = DNS::ProtocolType::TLS
    end

    def create_socket! : OpenSSL::SSL::Socket::Client
      socket = TCPSocket.new ip_address: ipAddress, connect_timeout: timeout.connect
      socket.read_timeout = timeout.read
      socket.write_timeout = timeout.write

      tls_context = tls.try &.unwrap || OpenSSL::SSL::Context::Client.new

      begin
        tls_socket = OpenSSL::SSL::Socket::Client.new socket, context: tls_context, sync_close: true, hostname: tls.try &.hostname
        tls_socket.close_after_finalize = true
        tls_socket.read_buffering = false
        tls_socket.ssl_context = tls_context
        tls_socket.sync = true
      rescue ex
        socket.close rescue nil
        tls_socket.try &.close rescue nil
        tls_context.free

        raise ex
      end

      tls_socket
    end
  end
end
