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

      {% if type == "ip_address" || type == "packet" || type == "ip_mapper" %}
        property answerStrictlySafe : Bool
      {% end %}

      {% if type == "ip_address" || type == "ip_mapper" %}
        property answerStrictlyIpv6 : Bool
      {% end %}

      {% if type == "service_mapper" %}
        def initialize(@capacity : Int32 = 512_i32)
        end
      {% elsif type == "packet" %}
        def initialize(@capacity : Int32 = 512_i32, @answerStrictlySafe : Bool = true)
        end
      {% else %}
        def initialize(@capacity : Int32 = 512_i32, @answerStrictlySafe : Bool = true, @answerStrictlyIpv6 : Bool = true)
        end
      {% end %}

      def unwrap
        {% if type == "packet" %}
          DNS::Caching::Packet.new capacity: capacity, answerStrictlySafe: answerStrictlySafe
        {% elsif type == "service_mapper" %}
          DNS::Caching::ServiceMapper.new capacity: capacity
        {% else %}
          DNS::Caching::IPAddress.new capacity: capacity, answerStrictlySafe: answerStrictlySafe, answerStrictlyIpv6: answerStrictlyIpv6
        {% end %}
      end
    end
    {% end %}
  end
end
