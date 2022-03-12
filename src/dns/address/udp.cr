abstract struct DNS::Address
  struct UDP < Address
    property ipAddress : Socket::IPAddress
    property timeout : TimeOut
    property protocolType : DNS::ProtocolType

    def initialize(@ipAddress : Socket::IPAddress, @timeout : TimeOut = TimeOut.new)
      @protocolType = DNS::ProtocolType::UDP
    end

    def create_socket! : UDPSocket
      socket = UDPSocket.new family: ipAddress.family
      socket.read_timeout = timeout.read
      socket.write_timeout = timeout.write
      socket.connect ip_address: ipAddress, connect_timeout: timeout.connect

      socket
    end
  end
end
