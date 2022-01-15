module DNS::Caching
  class IPAddress
    getter capacity : Int32
    getter clearInterval : Time::Span
    getter numberOfEntriesCleared : Int32
    getter answerStrictlySafe : Bool
    getter answerStrictlyIpv6 : Bool
    getter entries : Hash(String, Entry)
    getter lastCleanedUp : Time
    getter mutex : Mutex

    def initialize(@capacity : Int32 = 512_i32, @clearInterval : Time::Span = 3600_i32.seconds, @numberOfEntriesCleared : Int32 = ((capacity / 2_i32).to_i32 rescue 1_i32), @answerStrictlySafe : Bool = true, @answerStrictlyIpv6 : Bool = true)
      @entries = Hash(String, Entry).new
      @lastCleanedUp = Time.local
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

    private def refresh_last_cleaned_up
      @mutex.synchronize { @lastCleanedUp = Time.local }
    end

    private def need_cleared? : Bool
      interval = Time.local - (@mutex.synchronize { lastCleanedUp.dup })
      interval > clearInterval
    end

    def get_raw?(host : String, port : Int32? = nil, answer_safety_first : Bool? = nil, filter_type : Options::Addrinfo::FilterFlag = Options::Addrinfo::FilterFlag::IPV4_ONLY) : Array(Tuple(ProtocolType, Time::Span, Socket::IPAddress))?
      entry = @mutex.synchronize do
        return unless _entry = entries[host]?.dup

        _entry.refresh_last_visit
        _entry.add_visits
        entries[host] = _entry

        _entry
      end

      port = nil if port.zero? if port
      ip_addresses = entry.get_sort_ipaddresses answer_safety_first: answer_safety_first, filter_type: filter_type, port: port
      include_secure = false
      secure_time_to_live_end = true
      include_ipv6 = false
      ipv6_time_to_live_end = true

      _ip_addresses = ip_addresses.map do |tuple|
        protocol_type, ttl, _ip_address = tuple
        include_secure = true if protocol_type.tls? || protocol_type.https?
        include_ipv6 = true if _ip_address.family.inet6?

        next if (entry.createdAt + ttl) <= Time.local
        secure_time_to_live_end = false if protocol_type.tls? || protocol_type.https?
        ipv6_time_to_live_end = false if _ip_address.family.inet6?

        tuple
      end

      return if answerStrictlyIpv6 && include_ipv6 && (filter_type.ipv6_first? || filter_type.both?) && ipv6_time_to_live_end
      return if answerStrictlySafe && include_secure && secure_time_to_live_end

      _ip_addresses = _ip_addresses.compact
      return if _ip_addresses.empty?

      _ip_addresses
    end

    def get?(host : String, port : Int32, answer_safety_first : Bool? = nil, filter_type : Options::Addrinfo::FilterFlag = Options::Addrinfo::FilterFlag::IPV4_ONLY) : Array(Socket::IPAddress)?
      get_raw?(host: host, port: port, answer_safety_first: answer_safety_first).try &.map { |item| item.last }
    end

    def get?(host : String, answer_safety_first : Bool? = nil, filter_type : Options::Addrinfo::FilterFlag = Options::Addrinfo::FilterFlag::IPV4_ONLY) : Array(Socket::IPAddress)?
      get_raw?(host: host, answer_safety_first: answer_safety_first).try &.map { |item| item.last }
    end

    def set(host : String, ipv4_address : Tuple(ProtocolType, Time::Span, Socket::IPAddress), ipv6_address : Tuple(ProtocolType, Time::Span, Socket::IPAddress)? = nil)
      set host: host, ipv4_address: [ip_address_set], ipv6_address: ipv6_address ? [ipv6_address] : nil
    end

    def set(host : String, ipv4_addresses : Array(Tuple(ProtocolType, Time::Span, Socket::IPAddress)), ipv6_addresses : Array(Tuple(ProtocolType, Time::Span, Socket::IPAddress))? = nil)
      set host: host, ipv4_addresses: ipv4_addresses.to_set, ipv6_addresses: (ipv6_addresses || Array(Tuple(ProtocolType, Time::Span, Socket::IPAddress)).new).to_set
    end

    def set(host : String, ipv4_addresses : Set(Tuple(ProtocolType, Time::Span, Socket::IPAddress)), ipv6_addresses : Set(Tuple(ProtocolType, Time::Span, Socket::IPAddress))) : Entry
      entry = Entry.new ipv4Addresses: ipv4_addresses, ipv6Addresses: ipv6_addresses
      return entry if ipv4_addresses.empty? && ipv6_addresses.empty?

      inactive_entry_cleanup
      @mutex.synchronize { entries[host] = entry }

      entry
    end

    private def inactive_entry_cleanup
      case {full?, need_cleared?}
      when {true, false}
        clear_by_visits
        refresh_last_cleaned_up
      when {true, true}
        clear_by_last_visit
        refresh_last_cleaned_up
      end
    end

    {% for clear_type in ["last_visit", "visits"] %}
    private def clear_by_{{clear_type.id}}
      {% if clear_type.id == "last_visit" %}
        list = [] of Tuple(Time, String)
      {% elsif clear_type.id == "visits" %}
        list = [] of Tuple(Int64, String)
      {% end %}

      @mutex.synchronize do
        maximum_cleared = numberOfEntriesCleared - 1_i32
        maximum_cleared = 1_i32 if 1_i32 > maximum_cleared

        entries.each do |host, entry|
         {% if clear_type.id == "last_visit" %}
            list << Tuple.new entry.lastVisit, host
         {% elsif clear_type.id == "visits" %}
            list << Tuple.new entry.visits.get, host
         {% end %}
        end

        sorted_list = list.sort { |x, y| x.first <=> y.first }
        sorted_list.each_with_index do |tuple, index|
          break if index > maximum_cleared

          {% if clear_type.id == "last_visit" %}
            last_visit, host = tuple
          {% elsif clear_type.id == "visits" %}
            visits, host = tuple
          {% end %}

          entries.delete host
        end
      end
    end
    {% end %}

    struct Entry
      property ipv4Addresses : Set(Tuple(ProtocolType, Time::Span, Socket::IPAddress))
      property ipv6Addresses : Set(Tuple(ProtocolType, Time::Span, Socket::IPAddress))
      property lastVisit : Time
      property createdAt : Time
      property visits : Atomic(Int64)

      def initialize(@ipv4Addresses : Set(Tuple(ProtocolType, Time::Span, Socket::IPAddress)), @ipv6Addresses : Set(Tuple(ProtocolType, Time::Span, Socket::IPAddress)))
        @lastVisit = Time.local
        @createdAt = Time.local
        @visits = Atomic(Int64).new 0_i64
      end

      def add_visits
        @visits.add 1_i64
      end

      def refresh_last_visit
        @lastVisit = Time.local
      end

      def get_sort_ipaddresses(answer_safety_first : Bool?, filter_type : Options::Addrinfo::FilterFlag, port : Int32? = nil) : Array(Tuple(ProtocolType, Time::Span, Socket::IPAddress))
        list = __get_sort_ipaddresses answer_safety_first: answer_safety_first, filter_type: filter_type
        return list unless port

        tuple_list = [] of Tuple(ProtocolType, Time::Span, Socket::IPAddress)

        list.each do |tuple|
          protocol_type, ttl, ip_address = tuple
          tuple_list << Tuple.new protocol_type, ttl, Socket::IPAddress.new(address: ip_address.address, port: port)
        end

        tuple_list
      end

      private def __get_sort_ipaddresses(answer_safety_first : Bool?, filter_type : Options::Addrinfo::FilterFlag) : Array(Tuple(ProtocolType, Time::Span, Socket::IPAddress))
        case filter_type
        in .ipv4_first?
          merged_ip_addresses = ipv4Addresses.to_a.concat(ipv6Addresses.to_a)

          merged_ip_addresses.sort do |x, y|
            x_inet = x.last.family.inet? ? 0_u8 : 1_u8
            y_inet = y.last.family.inet? ? 0_u8 : 1_u8

            if answer_safety_first
              {SafetyFlag.from_protocol(protocol_flag: x.first), x_inet} <=> {SafetyFlag.from_protocol(protocol_flag: y.first), y_inet}
            else
              x_inet <=> y_inet
            end
          end
        in .ipv6_first?
          merged_ip_addresses = ipv6Addresses.to_a.concat(ipv4Addresses.to_a)

          merged_ip_addresses.sort do |x, y|
            x_inet6 = x.last.family.inet6? ? 0_u8 : 1_u8
            y_inet6 = y.last.family.inet6? ? 0_u8 : 1_u8

            if answer_safety_first
              {SafetyFlag.from_protocol(protocol_flag: x.first), x_inet6} <=> {SafetyFlag.from_protocol(protocol_flag: y.first), y_inet6}
            else
              x_inet6 <=> y_inet6
            end
          end
        in .ipv4_only?
          return ipv4Addresses.to_a unless answer_safety_first
          ipv4Addresses.to_a.sort { |x, y| SafetyFlag.from_protocol(protocol_flag: x.first) <=> SafetyFlag.from_protocol(protocol_flag: y.first) }
        in .ipv6_only?
          return ipv6Addresses.to_a unless answer_safety_first
          ipv6Addresses.to_a.sort { |x, y| SafetyFlag.from_protocol(protocol_flag: x.first) <=> SafetyFlag.from_protocol(protocol_flag: y.first) }
        in .both?
          merged_ip_addresses = ipv4Addresses.to_a.concat(ipv6Addresses.to_a)
          return merged_ip_addresses unless answer_safety_first
          merged_ip_addresses.sort { |x, y| SafetyFlag.from_protocol(protocol_flag: x.first) <=> SafetyFlag.from_protocol(protocol_flag: y.first) }
        end
      end
    end
  end
end
