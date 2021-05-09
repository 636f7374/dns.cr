module DNS::Caching
  class Packet
    getter capacity : Int32
    getter clearInterval : Time::Span
    getter numberOfEntriesCleared : Int32
    getter entries : Hash(String, Entry)
    getter latestCleanedUp : Time
    getter mutex : Mutex

    def initialize(@capacity : Int32 = 512_i32, @clearInterval : Time::Span = 3600_i32.seconds, @numberOfEntriesCleared : Int32 = ((capacity / 2_i32).to_i32 rescue 1_i32))
      @entries = Hash(String, Entry).new
      @latestCleanedUp = Time.local
      @mutex = Mutex.new :unchecked
    end

    def size
      @mutex.synchronize { entries.size }
    end

    def full?
      capacity <= self.size
    end

    def clear
      @mutex.synchronize { entries.clear }
    end

    private def refresh_latest_cleaned_up
      @mutex.synchronize { @latestCleanedUp = Time.local }
    end

    private def need_cleared? : Bool
      interval = Time.local - (@mutex.synchronize { latestCleanedUp.dup })
      interval > clearInterval
    end

    def get?(host : String, record_type : DNS::Packet::RecordFlag) : Array(DNS::Packet)?
      @mutex.synchronize do
        return unless entry = entries[host]?

        entry.refresh_latest_visit
        entry.add_visits
        entries[host] = entry

        {% begin %}
          case record_type
            {% for available_type in AvailableRecordFlags %}
          when .{{available_type.downcase.id}}?
            return if entry.{{available_type.downcase.id}}.empty?

            temporary = [] of DNS::Packet
            entry.{{available_type.downcase.id}}.each { |item| temporary << item }
            temporary
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
      set host: host, record_type: record_type, packets: packets.to_set
    end

    def set(host : String, record_type : DNS::Packet::RecordFlag, packets : Set(DNS::Packet))
      return if packets.empty?
      inactive_entry_cleanup

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

    private def inactive_entry_cleanup
      case {full?, need_cleared?}
      when {true, false}
        clear_by_visits
        refresh_latest_cleaned_up
      when {true, true}
        clear_by_latest_visit
        refresh_latest_cleaned_up
      end
    end

    {% for clear_type in ["latest_visit", "visits"] %}
    private def clear_by_{{clear_type.id}}
      {% if clear_type.id == "latest_visit" %}
        list = [] of Tuple(Time, String)
      {% elsif clear_type.id == "visits" %}
        list = [] of Tuple(Int64, String)
      {% end %}

      @mutex.synchronize do
        maximum_cleared = numberOfEntriesCleared - 1_i32
        maximum_cleared = 1_i32 if 1_i32 > maximum_cleared

        entries.each do |host, entry|
         {% if clear_type.id == "latest_visit" %}
            list << Tuple.new entry.latestVisit, host
         {% elsif clear_type.id == "visits" %}
            list << Tuple.new entry.visits.get, host
         {% end %}
        end

        sorted_list = list.sort { |x, y| x.first <=> y.first }
        sorted_list.each_with_index do |item, index|
          break if index > maximum_cleared
          entries.delete item.latest
        end
      end
    end
    {% end %}

    struct Entry
      property latestVisit : Time
      property visits : Atomic(Int64)

      def initialize
        @latestVisit = Time.local
        @visits = Atomic(Int64).new 0_i64
      end

      {% for record_type in AvailableRecordFlags %}
      def {{record_type.downcase.id}}=(value : Set(DNS::Packet))
        @{{record_type.downcase.id}} = value
      end

      def {{record_type.downcase.id}} : Set(DNS::Packet)
        @{{record_type.downcase.id}} ||= Set(DNS::Packet).new
      end
      {% end %}

      def add_visits
        @visits.add 1_i64
      end

      def refresh_latest_visit
        @latestVisit = Time.local
      end
    end
  end
end
