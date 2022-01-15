module DNS::Serialized
  abstract struct Address
    struct TLS < Address
      property ipAddress : String
      property timeout : TimeOut
      property tls : TransportLayerSecurity?

      def initialize(@ipAddress : String = "8.8.8.8:53", @timeout : TimeOut = TimeOut.new, @tls : TransportLayerSecurity? = nil)
      end

      def unwrap : DNS::Address?
        address, delimiter, port = ipAddress.rpartition ':'
        return unless _port = port.to_i?
        ip_address = Socket::IPAddress.new address: address, port: _port rescue nil
        return unless ip_address

        DNS::Address::TLS.new ipAddress: ip_address, timeout: timeout.unwrap, tls: tls.try &.unwrap
      end
    end
  end
end
