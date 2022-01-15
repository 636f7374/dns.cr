require "../src/dns.cr"

require "http/client"
require "http/request"

dns_servers = Set(DNS::Address).new
dns_servers << DNS::Address::UDP.new ipAddress: Socket::IPAddress.new("8.8.8.8", 53_i32)
dns_servers << DNS::Address::TCP.new ipAddress: Socket::IPAddress.new("8.8.4.4", 53_i32)
dns_servers << DNS::Address::TLS.new ipAddress: Socket::IPAddress.new("8.8.4.4", 853_i32)
dns_resolver = DNS::Resolver.new dnsServers: dns_servers, options: DNS::Options.new

# Create TCPSocket
socket = TCPSocket.new host: "www.example.com", port: 80_i32, dns_resolver: dns_resolver, connect_timeout: 10_i32.seconds, caller: nil

# Send HTTP::Request
http_request = HTTP::Request.new "GET", "http://www.example.com"
http_request.headers.add "Host", "www.example.com"
http_request.to_io io: socket

# Receive HTTP::Client::Response
http_response = HTTP::Client::Response.from_io io: socket
STDOUT.puts [:http, Time.local, http_response]
