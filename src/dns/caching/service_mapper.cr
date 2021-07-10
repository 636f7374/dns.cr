module DNS::Caching
  class ServiceMapper
    getter capacity : Int32
    getter clearInterval : Time::Span
    getter numberOfEntriesCleared : Int32
    getter entries : Hash(String, Entry)
    getter lastCleanedUp : Time
    getter mutex : Mutex

    def initialize(@capacity : Int32 = 512_i32, @clearInterval : Time::Span = 3600_i32.seconds, @numberOfEntriesCleared : Int32 = ((capacity / 2_i32).to_i32 rescue 1_i32))
      @entries = Hash(String, Entry).new
      @lastCleanedUp = Time.local
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

    private def refresh_last_cleaned_up
      @mutex.synchronize { @lastCleanedUp = Time.local }
    end

    private def need_cleared? : Bool
      interval = Time.local - (@mutex.synchronize { lastCleanedUp.dup })
      interval > clearInterval
    end

    def get?(host : String, port : Int32) : Entry?
      @mutex.synchronize do
        _address = String.build { |io| io << host << ':' << port }
        return unless entry = entries[_address]?

        entry.refresh_last_visit
        entry.add_visits
        entries[_address] = entry

        entry
      end
    end

    def set(host : String, port : Int32, dns_server : DNS::Address, options : Entry::Options = Entry::Options.new)
      dns_servers = Set(DNS::Packet).new
      dns_servers << dns_server

      set host: host, port: port, dns_servers: dns_servers, options: options
    end

    def set(host : String, port : Int32, dns_servers : Array(DNS::Address), options : Entry::Options = Entry::Options.new)
      set host: host, port: port, dns_servers: dns_servers.to_set, options: options
    end

    def set(host : String, port : Int32, dns_servers : Set(DNS::Address), options : Entry::Options = Entry::Options.new)
      inactive_entry_cleanup

      @mutex.synchronize do
        _address = String.build { |io| io << host << ':' << port }
        entry = entries[_address]? || Entry.new(dnsServers: dns_servers, options: options)

        entries[_address] = entry
      end
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
      property dnsServers : Set(DNS::Address)
      property options : Options
      property lastVisit : Time
      property visits : Atomic(Int64)

      def initialize(@dnsServers : Set(DNS::Address), @options : Options = Options.new)
        @lastVisit = Time.local
        @visits = Atomic(Int64).new 0_i64
      end

      def add_visits
        @visits.add 1_i64
      end

      def refresh_last_visit
        @lastVisit = Time.local
      end

      struct Options
        getter answerSafetyFirst : Bool
        getter overridable : Bool

        def initialize(@answerSafetyFirst : Bool = true, @overridable : Bool = true)
        end
      end
    end
  end
end
