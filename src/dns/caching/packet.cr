module DNS::Caching
  class Packet
    getter capacity : Int32
    getter answerStrictlySafe : Bool
    getter entries : Hash(String, Entry)
    getter mutex : Mutex

    def initialize(@capacity : Int32 = 512_i32, @answerStrictlySafe : Bool = true)
      @entries = Hash(String, Entry).new
      @mutex = Mutex.new :unchecked
    end

    def size
      @mutex.synchronize { entries.size.dup }
    end

    def full?
      capacity <= self.size
    end

    def clear
      @mutex.synchronize { entries.clear }
    end

    def get?(host : String, record_type : DNS::Packet::RecordFlag) : Array(DNS::Packet)?
      @mutex.synchronize do
        return unless entry = entries[host]?

        {% begin %}
          case record_type
            {% for available_type in AvailableRecordFlags %}
          when .{{available_type.downcase.id}}?
            return if entry.{{available_type.downcase.id}}.empty?

            packets = [] of DNS::Packet
            entry.{{available_type.downcase.id}}.each { |packet| packets << packet }
            packets
            {% end %}
          end
        {% end %}
      end
    end

    def set(host : String, record_type : DNS::Packet::RecordFlag, packet : DNS::Packet)
      packet_set = Set(DNS::Packet).new
      packet_set << packet

      set host: host, record_type: record_type, packets: packet_set
    end

    def set(host : String, record_type : DNS::Packet::RecordFlag, packets : Array(DNS::Packet))
      return if packets.empty?
      set host: host, record_type: record_type, packets: packets.to_set
    end

    def set(host : String, record_type : DNS::Packet::RecordFlag, packets : Set(DNS::Packet))
      return if packets.empty?
      @mutex.synchronize { entries.shift } if full?

      @mutex.synchronize do
        entry = entries[host]? || Entry.new

        {% begin %}
          case record_type
            {% for available_type in AvailableRecordFlags %}
          when .{{available_type.downcase.id}}?
            entry.{{available_type.downcase.id}} = packets
            {% end %}
          end
        {% end %}

        entries[host] = entry
      end
    end

    struct Entry
      getter createdAt : Time

      def initialize
        @createdAt = Time.local
      end

      {% for record_type in AvailableRecordFlags %}
      def {{record_type.downcase.id}}=(value : Set(DNS::Packet))
        @{{record_type.downcase.id}} = value
      end

      def {{record_type.downcase.id}} : Set(DNS::Packet)
        @{{record_type.downcase.id}} ||= Set(DNS::Packet).new
      end
      {% end %}
    end
  end
end
