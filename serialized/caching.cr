module DNS::Serialized
  struct Caching
    include YAML::Serializable

    property serviceMapper : ServiceMapper
    property ipAddress : IpAddress
    property packet : Packet
    property ipMapper : IpMapper

    def initialize(@serviceMapper : ServiceMapper, @ipAddress : IpAddress, @packet : Packet, @ipMapper : IpMapper)
    end

    {% for type in ["service_mapper", "ip_address", "packet", "ip_mapper"] %}
    struct {{type.camelcase.id}}
      include YAML::Serializable

      property capacity : Int32
      property clearInterval : Int32
      property numberOfEntriesCleared : Int32

      {% if type == "ip_address" || type == "packet" || type == "ip_mapper" %}
        property answerStrictlySafe : Bool
      {% end %}

      {% if type == "service_mapper" %}
        def initialize(@capacity : Int32 = 512_i32, @clearInterval : Int32 = 3600_i32, @numberOfEntriesCleared : Int32 = 256_i32)
        end
      {% else %}
        def initialize(@capacity : Int32 = 512_i32, @clearInterval : Int32 = 3600_i32, @numberOfEntriesCleared : Int32 = 256_i32, @answerStrictlySafe : Bool = true)
        end
      {% end %}

      def unwrap
        {% if type == "packet" %}
          DNS::Caching::Packet.new capacity: capacity, clearInterval: clearInterval.seconds, numberOfEntriesCleared: numberOfEntriesCleared, answerStrictlySafe: answerStrictlySafe
        {% elsif type == "service_mapper" %}
          DNS::Caching::ServiceMapper.new capacity: capacity, clearInterval: clearInterval.seconds, numberOfEntriesCleared: numberOfEntriesCleared
        {% else %}
          DNS::Caching::IPAddress.new capacity: capacity, clearInterval: clearInterval.seconds, numberOfEntriesCleared: numberOfEntriesCleared, answerStrictlySafe: answerStrictlySafe
        {% end %}
      end
    end
    {% end %}
  end
end
