#!/usr/bin/env ruby
# Read potentially sensitive response previews from stdin and print only
# aggregate parser outcomes. Do not log or persist the input.

require 'json'
require 'whois-parser'

hosts = { 'mn' => 'whois.nic.mn', 'cl' => 'whois.nic.cl', 'eu' => 'whois.eu' }
counts = Hash.new(0)

STDIN.each_line do |line|
  row = JSON.parse(line)
  tld = row.fetch('tld')
  klass = Whois::Parser.parser_klass(hosts.fetch(tld))
  parser = klass.new(Whois::Record::Part.new(body: row.fetch('raw')))
  expected = if row['registered'] == 'true'
    :registered
  elsif row['available'] == 'true'
    :available
  else
    :unknown
  end
  counts[[tld, expected, parser.status]] += 1
rescue StandardError => e
  counts[[tld || 'unknown', expected || :unknown, "error:#{e.class}"]] += 1
end

puts 'tld,api_classification,parser_classification,count'
counts.sort_by { |key, _count| key.map(&:to_s) }.each do |key, count|
  puts [*key, count].join(',')
end
