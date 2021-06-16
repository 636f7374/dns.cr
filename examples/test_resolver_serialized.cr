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
    maximumNumberOfRetriesForPerIpAddress: 1
    maximumNumberOfRetriesForIpv4ConnectionFailure: 6
    maximumNumberOfRetriesForIpv6ConnectionFailure: 2
  addrinfo:
    answerSafetyFirst: true
    maximumNumberOfMismatchRetries: 3
    enableProtection: true
    protectionWaitingTime: 5
    concurrentQuery: true
    queryType: ipv4_only
    filterType: ipv4_only
  packet:
    maximumCountOfQuestion: 128
    maximumCountOfAnswer: 128
    maximumCountOfAuthority: 128
    maximumCountOfAdditional: 128
    maximumDepthOfCanonicalName: 64
    maximumSizeOfPerChunk: 2048
    maximumSizeOfPacket: 65535
caching:
  serviceMapper:
    capacity: 512
    clearInterval: 3600
    numberOfEntriesCleared: 256
  ipAddress:
    capacity: 512
    clearInterval: 3600
    numberOfEntriesCleared: 256
    answerStrictlySafe: true
  ipMapper:
    capacity: 512
    clearInterval: 3600
    numberOfEntriesCleared: 256
    answerStrictlySafe: true
  packet:
    capacity: 512
    clearInterval: 3600
    numberOfEntriesCleared: 256
    answerStrictlySafe: true)

serialized = DNS::Serialized::Resolver.from_yaml text
STDOUT.puts [serialized.unwrap]
