#!/usr/bin/env ruby
# Consumes only the safe aggregate JSONL emitted by the on-host demand audit.
require 'csv'
require 'json'

columns = %w[namespace root requests registered_control_available].freeze
rows = ARGF.each_line.map { |line| JSON.parse(line) }
rows = rows.reject { |row| row.fetch('kind') == 'summary' }
rows.each do |row|
  raise 'Expected safe namespace aggregate' unless row.keys.sort == (columns + ['kind']).sort && row['kind'] == 'demand'
  raise 'Invalid namespace' unless row['namespace'].match?(/\A[a-z0-9-]+(?:\.[a-z0-9-]+)*\z/)
  raise 'Invalid root' unless row['root'].match?(/\A[a-z0-9-]+\z/)
  raise 'Invalid request count' unless row['requests'].is_a?(Integer) && row['requests'].positive?
  raise 'Invalid control flag' unless [true, false].include?(row['registered_control_available'])
end
raise 'Duplicate namespace' unless rows.map { |row| row['namespace'] }.uniq.length == rows.length

CSV($stdout) do |csv|
  csv << columns
  rows.each { |row| csv << columns.map { |column| row.fetch(column) } }
end
