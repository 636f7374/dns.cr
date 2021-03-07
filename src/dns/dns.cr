module DNS
  AvailableRecordFlags = Set{"A", "AAAA", "NS", "PTR", "CNAME", "SOA", "TXT", "MX", "DNAME", "SRV", "OPT"}

  enum ProtocolType : UInt8
    UDP = 0_u8
    TCP = 1_u8
    TLS = 2_u8
  end

  enum FetchType : UInt8
    Server  = 0_u8
    Local   = 1_u8
    Caching = 2_u8
    Mapper  = 3_u8
  end
end
