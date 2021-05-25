module DNS::Serialized
  struct Resolver
    include YAML::Serializable

    property servers : Array(Address)
    property caching : Caching
    property options : Serialized::Options::Standard

    def initialize(@servers : Array(Address) = [Address.new] of Address, @caching : Caching = Caching.new, @options : Serialized::Options::Standard = Serialized::Options::Standard.new)
    end

    def unwrap : DNS::Resolver
      DNS::Resolver.new dnsServers: unwrap_servers, options: unwrap_options, ipAddressCaching: caching.ipAddress.unwrap, packetCaching: caching.packet.unwrap, mapperCaching: caching.mapper.unwrap
    end

    def unwrap_servers : Set(DNS::Address)
      list = Set(DNS::Address).new

      servers.each do |server|
        next unless address = server.unwrap
        list << address
      end

      list
    end

    def unwrap_caching_packet : DNS::Caching::Packet
      caching.packet.unwrap
    end

    def unwrap_caching_ip_address : DNS::Caching::IPAddress
      caching.ipAddress.unwrap
    end

    def unwrap_caching_mapper : DNS::Caching::IPAddress
      caching.mapper.unwrap
    end

    def unwrap_options : DNS::Options
      options.unwrap
    end
  end
end
