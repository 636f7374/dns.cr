class DNS::Resolver
  class GetAddrinfoProtector
    getter list : Set(String)
    getter mutex : Mutex

    def initialize(@list : Set(String) = Set(String).new)
      @mutex = Mutex.new :unchecked
    end

    def delete(host : String) : Bool
      @mutex.synchronize { list.delete host }

      true
    end

    def includes?(host : String) : Bool
      @mutex.synchronize { list.includes? host }
    end

    def set(host : String) : Bool
      return false if includes? host: host
      @mutex.synchronize { list << host }

      true
    end
  end
end
