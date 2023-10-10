module DNS::Serialized
  abstract struct Address
    struct TLS < Address
      property ipAddress : String
      property timeout : TimeOut
      property tls : TransportLayerSecurity?

      def initialize(@ipAddress : String = "8.8.8.8:53", @timeout : TimeOut = TimeOut.new, @tls : TransportLayerSecurity? = nil)
      end

      def unwrap : DNS::Address?
        return unless ip_address = Address.unwrap_ip_address ip_address: ipAddress
        DNS::Address::TLS.new ipAddress: ip_address, timeout: timeout.unwrap, tls: tls.try &.unwrap
      end
    end
  end
end
