require "../src/dns.cr"
require "../serialization/serialization.cr"
require "../serialization/*"

text = %(servers:
  - ipAddress: 8.8.8.8:53
    protocolType: udp
    timeout:
      read: 2
      write: 2
      connect: 2
  - ipAddress: 8.8.4.4:53
    protocolType: tls
    tls:
      hostname: dns.google
      options:
        - no_ssl_v2
        - no_ssl_v3
        - no_tls_v1
        - no_tls_v1_1
        - no_tls_v1_2
    timeout:
      read: 2
      write: 2
      connect: 2
caching:
  capacity: 512
  clearInterval: 3600
  numberOfEntriesCleared: 256
options:
  socket:
    ipv4ConnectionFailureRetryTimes: 2
    ipv6ConnectionFailureRetryTimes: 2
  addrinfo:
    answerSafetyFirst: true
    maximumNumberOfMismatchRetries: 3
    enableProtection: true
    protectionWaitingTime: 5
    concurrentQuery: true
    queryIpv6: false
    filterType: ipv4_only
    maximumCanonicalNameDepth: 64)

serialization = DNS::Serialization::Resolver.from_yaml text
STDOUT.puts [serialization.unwrap]
