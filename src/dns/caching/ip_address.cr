module DNS::Caching
  class IPAddress
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

    private def refresh_latest_cleaned_up
      @mutex.synchronize { @latestCleanedUp = Time.local }
    end

    private def need_cleared? : Bool
      interval = Time.local - (@mutex.synchronize { latestCleanedUp })
      interval > clearInterval
    end

    def get?(host : String, port : Int32) : Array(Socket::IPAddress)?
      @mutex.synchronize do
        return unless entry = entries[host]?

        entry.refresh_last_visit
        entry.add_visits
        entries[host] = entry

        ip_addresses = [] of Socket::IPAddress

        entry.ipAddresses.each do |ip_address|
          ip_addresses << Socket::IPAddress.new address: ip_address.address, port: port
        end

        return if ip_addresses.empty?
        ip_addresses
      end
    end

    def set(host : String, ip_address : Socket::IPAddress)
      ip_address_set = Set(Socket::IPAddress).new
      ip_address_set << ip_address

      set host: host, ip_addresses: ip_address_set
    end

    def set(host : String, ip_addresses : Array(Socket::IPAddress))
      set host: host, ip_addresses: ip_addresses.to_set
    end

    def set(host : String, ip_addresses : Set(Socket::IPAddress))
      return if ip_addresses.empty?
      inactive_entry_cleanup

      entry = Entry.new ipAddresses: ip_addresses
      @mutex.synchronize { entries[host] = entry }
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
          entries.delete item.last
        end
      end
    end
    {% end %}

    struct Entry
      property ipAddresses : Set(Socket::IPAddress)
      property latestVisit : Time
      property visits : Atomic(Int64)

      def initialize(@ipAddresses : Set(Socket::IPAddress))
        @latestVisit = Time.local
        @visits = Atomic(Int64).new 0_i64
      end

      def add_visits
        @visits.add 1_i64
      end

      def refresh_last_visit
        @latestVisit = Time.local
      end
    end
  end
end
