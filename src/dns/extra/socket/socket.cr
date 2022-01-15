class Socket
  def connect(ip_address : IPAddress, connect_timeout = nil)
    Addrinfo.build_addrinfo ip_address: ip_address, family: @family, type: @type, protocol: @protocol do |addrinfo|
      connect(addrinfo, timeout: connect_timeout) { |error| error }
    end
  end
end
