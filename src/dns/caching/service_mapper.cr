module DNS::Caching
  class ServiceMapper
    getter capacity : Int32
    getter entries : Hash(String, Entry)
    getter mutex : Mutex

    def initialize(@capacity : Int32 = 512_i32)
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

    def get?(host : String, port : Int32) : Entry?
      _address = String.build { |io| io << host << ':' << port }
      @mutex.synchronize { entries[_address]? }
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
      @mutex.synchronize { entries.shift } if full?
      _address = String.build { |io| io << host << ':' << port }

      @mutex.synchronize do
        entry = entries[_address]? || Entry.new(dnsServers: dns_servers, options: options)
        entries[_address] = entry
      end
    end

    struct Entry
      property dnsServers : Set(DNS::Address)
      property options : Options
      getter createdAt : Time

      def initialize(@dnsServers : Set(DNS::Address), @options : Options = Options.new)
        @createdAt = Time.local
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
