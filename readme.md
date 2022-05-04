<div align = "center"><img src="images/icon.png" width="256" height="256" /></div>

<div align = "center">
  <h1>Dns.cr - Domain Name System Resolver</h1>
</div>

<p align="center">
  <a href="https://crystal-lang.org">
    <img src="https://img.shields.io/badge/built%20with-crystal-000000.svg" /></a>    
  <a href="https://github.com/636f7374/dns.cr/actions">
    <img src="https://github.com/636f7374/dns.cr/workflows/Continuous%20Integration/badge.svg" /></a>
  <a href="https://github.com/636f7374/dns.cr/releases">
    <img src="https://img.shields.io/github/release/636f7374/dns.cr.svg" /></a>
  <a href="https://github.com/636f7374/dns.cr/blob/master/license">
    <img src="https://img.shields.io/github/license/636f7374/dns.cr.svg"></a>
</p>

## Description

* High-performance, reliable, and stable DNS Resolver.
* This repository is under evaluation and will replace [Durian.cr](https://github.com/636f7374/durian.cr).

## Features

* [X] Concurrent
* [X] Caching
* [X] UDP
* [X] DNS over T(CP/LS)
* [X] DNS over HTTP(S)

## Usage

* Please check the examples folder.

### Used as Shard

Add this to your application's shard.yml:

```yaml
dependencies:
  dns:
    github: 636f7374/dns.cr
```

### Installation

```bash
$ git clone https://github.com/636f7374/dns.cr.git
```

## Development

```bash
$ make test
```

## References

* [StackOverflow | How to convert a string or integer to binary in Ruby?](https://stackoverflow.com/questions/2339695/how-to-convert-a-string-or-integer-to-binary-in-ruby)
* [StackOverflow | Requesting A and AAAA records in single DNS query](https://stackoverflow.com/questions/4082081/requesting-a-and-aaaa-records-in-single-dns-query)
* [StackOverflow | Example of DNS Compression Pointer Offset > than 12 bytes](https://stackoverflow.com/questions/39439283/example-of-dns-compression-pointer-offset-than-12-bytes)
* [StackOverflow | why libuv do DNS request by multiple thread](https://stackoverflow.com/questions/44603059/why-libuv-do-dns-request-by-multiple-thread)
* [Official | DNS_HEADER structure](https://docs.microsoft.com/en-us/windows/win32/api/windns/ns-windns-dns_header)
* [Official | The Saga of Concurrent DNS in Python, and the Defeat of the Wicked Mutex Troll](https://engineering.mongodb.com/post/the-saga-of-concurrent-dns-in-python-and-the-defeat-of-the-wicked-mutex-troll)
* [Official | Help understanding DNS packet data](https://osqa-ask.wireshark.org/questions/50806/help-understanding-dns-packet-data)
* [Official | Ietf - RFC 1035](https://www.ietf.org/rfc/rfc1035.txt)
* [Official | Docs.rs::hyper_trust_dns_connector](https://docs.rs/hyper-trust-dns-connector/0.1.0/hyper_trust_dns_connector/)
* [Official | libuv provides asynchronous variants of getaddrinfo and getnameinfo](http://docs.libuv.org/en/v1.x/dns.html)
* [Blogs | Adventures in Rust: Futures and Tokio](https://bryangilbert.com/post/code/rust/adventures-futures-tokio-rust/)
* [Blogs | Cocoa: Asynchronous Host name lookups](https://eggerapps.at/blog/2014/hostname-lookups.html)
* [Blogs | Using DNS with Libevent: high and low-level functionality](http://www.wangafu.net/~nickm/libevent-book/Ref9_dns.html)
* [Blogs | The problem with libresolv](https://skarnet.org/software/s6-dns/libresolv.html)
* [Blogs | The problem with getaddrinfo](https://skarnet.org/software/s6-dns/getaddrinfo.html)
* [Blogs | What does getaddrinfo do?](https://jameshfisher.com/2018/02/03/what-does-getaddrinfo-do/)
* [Blogs | A warm welcome to DNS](https://powerdns.org/hello-dns/basic.md.html)
* [Document | DNS Query Message Format](http://www.firewall.cx/networking-topics/protocols/domain-name-system-dns/160-protocols-dns-query.html)
* [Docuemnt | Protocol and Format](http://www-inf.int-evry.fr/~hennequi/CoursDNS/NOTES-COURS_eng/msg.html)
* [Document | Binary Numbers](http://www.oualline.com/practical.programmer/numbers.html)
* [Document | DNS Message Header and Question Section Format](http://www.tcpipguide.com/free/t_DNSMessageHeaderandQuestionSectionFormat.htm)
* [Document | DNS Name Notation and Message Compression Technique](http://www.tcpipguide.com/free/t_DNSNameNotationandMessageCompressionTechnique-2.htm)
* [Github Gist | DNS Query Code in C with linux sockets](https://gist.github.com/fffaraz/9d9170b57791c28ccda9255b48315168)
* [Github Gist | getaddrinfo.strace](https://gist.github.com/alq666/4683879)
* [Source Code | posix/getaddrinfo.c](https://code.woboq.org/userspace/glibc/sysdeps/posix/getaddrinfo.c.html#getaddrinfo)
* [Source Code | DNS header for C | 0x00sec](https://0x00sec.org/t/dns-header-for-c/618)
* ...

## Related

* [#8480 | blocking call in one fiber can cause IO timeouts in others](https://github.com/crystal-lang/crystal/issues/8480)
* [#4816 | Add Resolv class to standard library](https://github.com/crystal-lang/crystal/issues/4816)
* [#2660 | Fix/Implement own DNS resolver](https://github.com/crystal-lang/crystal/issues/2660)
* [#4236 | Configurable DNS resolvers](https://github.com/crystal-lang/crystal/pull/4236)
* [#2829 | DNS threaded resolver](https://github.com/crystal-lang/crystal/pull/2829)
* [#2745 | Don't use libevent's getaddrinfo, use C's getaddrinfo](https://github.com/crystal-lang/crystal/pull/2745)
* [#8376 | Some TCPSocket connections will cause HTTP::Server accept (freeze | blocking | hangs | waiting)?](https://github.com/crystal-lang/crystal/issues/8376)
* ...

## Credit

* [\_Icon::Freepik/Travel](https://www.flaticon.com/packs/travel-321)

## Contributors

|Name|Creator|Maintainer|Contributor|
|:---:|:---:|:---:|:---:|
|**[636f7374](https://github.com/636f7374)**|√|√|√|
|**[usiegj00](https://github.com/usiegj00)**|||√|

## License

* BSD 3-Clause Clear License
