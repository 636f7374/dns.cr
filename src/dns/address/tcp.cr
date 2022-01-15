abstract struct DNS::Address
  struct TCP < Address
    property ipAddress : Socket::IPAddress
    property timeout : TimeOut
    property protocolType : DNS::ProtocolType

    def initialize(@ipAddress : Socket::IPAddress, @timeout : TimeOut = TimeOut.new)
      @protocolType = DNS::ProtocolType::TCP
    end

    def create_socket! : Tuple(OpenSSL::SSL::Context::Client?, TCPSocket)
      socket = TCPSocket.new ip_address: ipAddress, connect_timeout: timeout.connect
      socket.read_timeout = timeout.read
      socket.write_timeout = timeout.write

      Tuple.new nil, socket
    end
  end
end
