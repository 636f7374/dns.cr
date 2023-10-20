require "../src/dns.cr"
require "../serialized/serialized.cr"
require "../serialized/*"

text = %(servers:
  - ipAddress: 8.8.8.8:53
    timeout:
      read: 2
      write: 2
      connect: 2
    protocolType: udp



  - ipAddress: 8.8.4.4:53
    timeout:
      read: 2
      write: 2
      connect: 2
    protocolType: tcp



  - ipAddress: 8.8.8.8:53
    method: GET
    path: /dns-query
    parameters:
      - parameter_a: B
      - parameter_b: C
      - dns:
    headers:
      - Accept: application/dns-message
      - Host: 8.8.8.8:53
    timeout:
      read: 2
      write: 2
      connect: 2
    protocolType: http



  - ipAddress: 8.8.4.4:53
    method: GET
    path: /dns-query?dns=
    headers:
      - Accept: application/dns-message
      - Host: 8.8.8.8:53
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
    protocolType: https



  - ipAddress: 8.8.8.8:853
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
    protocolType: tls
options:
  socket:
    maximumIpv4Attempts: 6
    maximumIpv6Attempts: 2
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
    answerStrictlyIpv6: true
  ipMapper:
    capacity: 512
    clearInterval: 3600
    numberOfEntriesCleared: 256
    answerStrictlySafe: true
    answerStrictlyIpv6: true
  packet:
    capacity: 512
    clearInterval: 3600
    numberOfEntriesCleared: 256
    answerStrictlySafe: true)

serialized = DNS::Serialized::Resolver.from_yaml text
STDOUT.puts [serialized.unwrap]
