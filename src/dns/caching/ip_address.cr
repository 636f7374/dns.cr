module DNS::Caching
  class IPAddress
    getter capacity : Int32
    getter clearInterval : Time::Span
    getter numberOfEntriesCleared : Int32
    getter answerStrictlySafe : Bool
    getter entries : Hash(String, Entry)
    getter latestCleanedUp : Time
    getter mutex : Mutex

    def initialize(@capacity : Int32 = 512_i32, @clearInterval : Time::Span = 3600_i32.seconds, @numberOfEntriesCleared : Int32 = ((capacity / 2_i32).to_i32 rescue 1_i32), @answerStrictlySafe : Bool = true)
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

    def get_raw?(host : String, port : Int32? = nil, answer_safety_first : Bool? = nil) : Array(Tuple(ProtocolType, Time::Span, Socket::IPAddress))?
      @mutex.synchronize do
        return unless entry = entries[host]?
        starting_time = Time.local

        entry.refresh_latest_visit
        entry.add_visits
        entries[host] = entry

        entry.ipAddresses = entry.ip_addresses_sort_by_protocol if answer_safety_first
        secure_time_to_live_end = true

        _ip_addresses = entry.ipAddresses.map do |tuple|
          protocol_type, ttl, _ip_address = tuple
          next if (entry.createdAt + ttl) <= starting_time
          secure_time_to_live_end = false if protocol_type.tls? || protocol_type.https?

          next tuple unless port
          Tuple.new protocol_type, ttl, Socket::IPAddress.new address: _ip_address.address, port: port
        end

        return if answerStrictlySafe && secure_time_to_live_end
        _ip_addresses = _ip_addresses.compact
        return if _ip_addresses.empty?

        _ip_addresses
      end
    end

    def get?(host : String, port : Int32, answer_safety_first : Bool? = nil) : Array(Socket::IPAddress)?
      get_raw?(host: host, port: port, answer_safety_first: answer_safety_first).try &.map { |item| item.last }
    end

    def get?(host : String, answer_safety_first : Bool? = nil) : Array(Socket::IPAddress)?
      get_raw?(host: host, answer_safety_first: answer_safety_first).try &.map { |item| item.last }
    end

    def set(host : String, ip_address : Tuple(ProtocolType, Time::Span, Socket::IPAddress))
      ip_address_set = Set(Tuple(ProtocolType, Time::Span, Socket::IPAddress)).new
      ip_address_set << ip_address

      set host: host, ip_addresses: ip_address_set
    end

    def set(host : String, ip_addresses : Array(Tuple(ProtocolType, Time::Span, Socket::IPAddress)))
      set host: host, ip_addresses: ip_addresses.to_set
    end

    def set(host : String, ip_addresses : Set(Tuple(ProtocolType, Time::Span, Socket::IPAddress)))
      return if ip_addresses.empty?
      inactive_entry_cleanup

      @mutex.synchronize { entries[host] = Entry.new ipAddresses: ip_addresses }
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
        sorted_list.each_with_index do |tuple, index|
          break if index > maximum_cleared

          {% if clear_type.id == "latest_visit" %}
            latest_visit, host = tuple
          {% elsif clear_type.id == "visits" %}
            visits, host = tuple
          {% end %}

          entries.delete host
        end
      end
    end
    {% end %}

    struct Entry
      property ipAddresses : Set(Tuple(ProtocolType, Time::Span, Socket::IPAddress))
      property latestVisit : Time
      property createdAt : Time
      property visits : Atomic(Int64)

      def initialize(@ipAddresses : Set(Tuple(ProtocolType, Time::Span, Socket::IPAddress)))
        @latestVisit = Time.local
        @createdAt = Time.local
        @visits = Atomic(Int64).new 0_i64
      end

      def add_visits
        @visits.add 1_i64
      end

      def refresh_latest_visit
        @latestVisit = Time.local
      end

      def ip_addresses_sort_by_protocol : Set(Tuple(ProtocolType, Time::Span, Socket::IPAddress))
        ipAddresses.to_a.sort { |x, y| SafetyFlag.from_protocol(protocol_flag: x.first) <=> SafetyFlag.from_protocol(protocol_flag: y.first) }.to_set
      end
    end
  end
end
