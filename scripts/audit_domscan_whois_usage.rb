#!/usr/bin/env ruby
# Compare aggregate DomScan usage with the parser's current host mappings.
# A parser class is structural coverage only; it is not evidence of a correct
# registration decision for a live registry response.

require 'csv'
require 'whois-parser'

path = ARGV.fetch(0)
rows = CSV.read(path, headers: true)
relay_hosts = {
  'africa' => 'whois.nic.africa',
  'ge' => 'whois.nic.ge',
  'io' => 'whois.nic.io',
  'pk' => 'whois.pknic.net.pk',
  'sr' => 'whois.sr',
}

puts 'tld,traditional_whois_used,whois_host,parser_class'
rows.select { |row| row.fetch('traditional_whois_used').to_i.positive? }.each do |row|
  tld = row.fetch('tld')
  sample = tld == 'za' ? 'example.co.za' : "example.#{tld}"
  server = Whois::Server.find_for_domain(sample)
  host = relay_hosts.fetch(tld, server&.host)
  parser = begin
    Whois::Parser.parser_klass(host) if host
  rescue LoadError, Whois::ParserNotFound
    nil
  end
  puts [tld, row.fetch('traditional_whois_used'), host || 'no-server', parser&.name || 'no-parser'].join(',')
end
