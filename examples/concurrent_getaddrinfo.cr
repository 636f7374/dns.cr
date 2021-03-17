require "../src/dns.cr"

# In this example, we use concurrent to getaddrinfo.
# You can even use `DNS::Resolver::Options` to adjust as needed.
# We can query the results through UDP, TCP and TLS.

dns_servers = Set(DNS::Address).new
dns_servers << DNS::Address.new ipAddress: Socket::IPAddress.new("8.8.8.8", 53_i32), protocolType: DNS::ProtocolType::UDP
dns_servers << DNS::Address.new ipAddress: Socket::IPAddress.new("8.8.4.4", 53_i32), protocolType: DNS::ProtocolType::TCP
dns_servers << DNS::Address.new ipAddress: Socket::IPAddress.new("8.8.4.4", 853_i32), protocolType: DNS::ProtocolType::TLS
dns_resolver = DNS::Resolver.new dnsServers: dns_servers, options: DNS::Options.new

concurrent_mutex = Mutex.new :unchecked
concurrent_fibers = Set(Fiber).new
reply_mutex = Mutex.new :unchecked
reply_packets = Set(Tuple(String, Time::Span, Tuple(DNS::FetchType, Array(Socket::IPAddress)))).new

main_concurrent_fibers = spawn do
  rust_query_fiber = spawn do
    before = Time.local
    packets = dns_resolver.getaddrinfo host: "rust-lang.org", port: 443_i32
    after = Time.local
    reply_mutex.synchronize { reply_packets << Tuple.new "rust-lang.org", (after - before), packets }
  end

  concurrent_mutex.synchronize { concurrent_fibers << rust_query_fiber }

  crystal_query_fiber = spawn do
    before = Time.local
    packets = dns_resolver.getaddrinfo host: "crystal-lang.org", port: 443_i32
    after = Time.local
    reply_mutex.synchronize { reply_packets << Tuple.new "crystal-lang.org", (after - before), packets }
  end

  concurrent_mutex.synchronize { concurrent_fibers << crystal_query_fiber }

  github_query_fiber = spawn do
    before = Time.local
    packets = dns_resolver.getaddrinfo host: "github.com", port: 443_i32
    after = Time.local
    reply_mutex.synchronize { reply_packets << Tuple.new "github.com", (after - before), packets }
  end

  concurrent_mutex.synchronize { concurrent_fibers << github_query_fiber }

  crystal_again_query_fiber = spawn do
    before = Time.local
    packets = dns_resolver.getaddrinfo host: "crystal-lang.org", port: 443_i32
    after = Time.local
    reply_mutex.synchronize { reply_packets << Tuple.new "crystal-lang.org", (after - before), packets }
  end

  concurrent_mutex.synchronize { concurrent_fibers << crystal_again_query_fiber }

  medium_query_fiber = spawn do
    before = Time.local
    packets = dns_resolver.getaddrinfo host: "medium.com", port: 443_i32
    after = Time.local
    reply_mutex.synchronize { reply_packets << Tuple.new "medium.com", (after - before), packets }
  end

  concurrent_mutex.synchronize { concurrent_fibers << medium_query_fiber }
end

concurrent_mutex.synchronize { concurrent_fibers << main_concurrent_fibers }

loop do
  all_dead = concurrent_mutex.synchronize { concurrent_fibers.all? { |fiber| fiber.dead? } }
  next sleep 0.25_f32.seconds unless all_dead

  reply_mutex.synchronize do
    STDOUT.puts reply_packets.map { |tuple| Tuple.new tuple.first, tuple.last }
    STDOUT.puts reply_packets.map { |tuple| Tuple.new tuple.first, tuple[1_i32] }
  end

  break
end
