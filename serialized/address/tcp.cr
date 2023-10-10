module DNS::Serialized
  abstract struct Address
    struct TCP < Address
      property ipAddress : String
      property timeout : TimeOut

      def initialize(@ipAddress : String = "8.8.8.8:53", @timeout : TimeOut = TimeOut.new)
      end

      def unwrap : DNS::Address?
        return unless ip_address = Address.unwrap_ip_address ip_address: ipAddress
        DNS::Address::TCP.new ipAddress: ip_address, timeout: timeout.unwrap
      end
    end
  end
end
