abstract struct DNS::Address
  struct HTTP < Address
    property ipAddress : Socket::IPAddress
    property timeout : TimeOut
    property method : String
    property resource : String
    property headers : ::HTTP::Headers
    property protocolType : DNS::ProtocolType

    def initialize(@ipAddress : Socket::IPAddress, @timeout : TimeOut = TimeOut.new, @method : String = "GET", @resource : String = "/dns-query?dns=", @headers : ::HTTP::Headers = ::HTTP::Headers.new)
      @protocolType = DNS::ProtocolType::HTTP
    end

    def create_socket! : TCPSocket
      socket = TCPSocket.new ip_address: ipAddress, connect_timeout: timeout.connect
      socket.read_timeout = timeout.read
      socket.write_timeout = timeout.write

      socket
    end
  end
end
