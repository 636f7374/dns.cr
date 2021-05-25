module DNS::Serialized
  struct Caching
    include YAML::Serializable

    property ipAddress : IpAddress
    property packet : Packet
    property mapper : Mapper

    def initialize(@ipAddress : IpAddress, @packet : Packet, @mapper : Mapper)
    end

    {% for type in ["ip_address", "packet", "mapper"] %}
    struct {{type.camelcase.id}}
      include YAML::Serializable

      property capacity : Int32
      property clearInterval : Int32
      property numberOfEntriesCleared : Int32

      def initialize(@capacity : Int32 = 512_i32, @clearInterval : Int32 = 3600_i32, @numberOfEntriesCleared : Int32 = 256_i32)
      end

      def unwrap
        {% if type == "packet" %}
          DNS::Caching::Packet.new capacity: capacity, clearInterval: clearInterval.seconds, numberOfEntriesCleared: numberOfEntriesCleared
        {% else %}
          DNS::Caching::IPAddress.new capacity: capacity, clearInterval: clearInterval.seconds, numberOfEntriesCleared: numberOfEntriesCleared
        {% end %}
      end
    end
    {% end %}
  end
end
