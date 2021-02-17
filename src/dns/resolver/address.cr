class DNS::Resolver
  struct Address
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
        socket = TCPSocket.new ip_address: ipAddress, connect_timeout: timeout.connect
        socket.read_timeout = timeout.read
        socket.write_timeout = timeout.write

        begin
          openssl_context = OpenSSL::SSL::Context::Client.new
        rescue ex
          socket.close rescue nil

          raise ex
        end

        begin
          tls_socket = OpenSSL::SSL::Socket::Client.new socket, context: openssl_context, sync_close: true, hostname: tls.try &.hostname
          tls_socket.sync = true
        rescue ex
          socket.close rescue nil
          openssl_context.skip_finalize = true
          openssl_context.free

          raise ex
        end

        Tuple.new openssl_context, tls_socket
      end
    end

    struct TransportLayerSecurity
      property hostname : String?

      def initialize(@hostname : String? = nil)
      end
    end
  end
end
