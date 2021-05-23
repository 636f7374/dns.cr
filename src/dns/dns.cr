module DNS
  AvailableRecordFlags = Set{"A", "AAAA", "NS", "PTR", "CNAME", "SOA", "TXT", "MX", "DNAME", "SRV", "OPT"}

  enum ProtocolType : UInt8
    UDP   = 0_u8
    TCP   = 1_u8
    TLS   = 2_u8
    HTTP  = 3_u8
    HTTPS = 4_u8
  end

  enum SafetyFlag : UInt8
    HTTPS = 0_u8
    TLS   = 1_u8
    HTTP  = 2_u8
    TCP   = 3_u8
    UDP   = 4_u8

    def self.from_protocol(protocol_flag : ProtocolType) : SafetyFlag
      case protocol_flag
      in .udp?
        SafetyFlag::UDP
      in .tcp?
        SafetyFlag::TCP
      in .tls?
        SafetyFlag::TLS
      in .http?
        SafetyFlag::HTTP
      in .https?
        SafetyFlag::HTTPS
      end
    end
  end

  enum FetchType : UInt8
    Remote   = 0_u8
    Local    = 1_u8
    Caching  = 2_u8
    Mapper   = 3_u8
    Override = 4_u8
  end
end
