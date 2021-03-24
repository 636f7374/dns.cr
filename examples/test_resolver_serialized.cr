require "../src/dns.cr"
require "../serialized/serialized.cr"
require "../serialized/*"

text = %(servers:
  - ipAddress: 8.8.4.4:53
    protocolType: udp
    timeout:
      read: 2
      write: 2
      connect: 2
  - ipAddress: 8.8.4.4:853
    protocolType: tls
    timeout:
      read: 2
      write: 2
      connect: 2
    tls:
      hostname: dns.google
      verifyMode: peer
      options:
        - no_ssl_v2
        - no_ssl_v3
        - no_tls_v1
        - no_tls_v1_1
        - no_tls_v1_2
  - ipAddress: 8.8.8.8:853
    protocolType: tls
    timeout:
      read: 2
      write: 2
      connect: 2
    tls:
      hostname: dns.google
      verifyMode: peer
      options:
        - no_ssl_v2
        - no_ssl_v3
        - no_tls_v1
        - no_tls_v1_1
        - no_tls_v1_2
options:
  socket:
    maximumTimesOfIpv4ConnectionFailureRetries: 6
    maximumTimesOfIpv6ConnectionFailureRetries: 2
  addrinfo:
    answerSafetyFirst: true
    maximumNumberOfMismatchRetries: 3
    enableProtection: true
    protectionWaitingTime: 5
    concurrentQuery: true
    queryIpv6: false
    filterType: ipv4_only
    maximumDepthOfCanonicalName: 64
caching:
  ipAddress:
    capacity: 512
    clearInterval: 3600
    numberOfEntriesCleared: 256
  mapper:
    capacity: 512
    clearInterval: 3600
    numberOfEntriesCleared: 256
  packet:
    capacity: 512
    clearInterval: 3600
    numberOfEntriesCleared: 256)

serialized = DNS::Serialized::Resolver.from_yaml text
STDOUT.puts [serialized.unwrap]