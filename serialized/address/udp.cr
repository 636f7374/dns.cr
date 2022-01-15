module DNS::Serialized
  abstract struct Address
    struct UDP < Address
      property ipAddress : String
      property timeout : TimeOut

      def initialize(@ipAddress : String = "8.8.8.8:53", @timeout : TimeOut = TimeOut.new)
      end

      def unwrap : DNS::Address?
        address, delimiter, port = ipAddress.rpartition ':'
        return unless _port = port.to_i?
        ip_address = Socket::IPAddress.new address: address, port: _port rescue nil
        return unless ip_address

        DNS::Address::UDP.new ipAddress: ip_address, timeout: timeout.unwrap
      end
    end
  end
end
