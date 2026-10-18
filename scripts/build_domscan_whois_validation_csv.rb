#!/usr/bin/env ruby
# Builds a privacy-safe dated capability scorecard, never an accuracy estimate.
require 'csv'
require 'json'
require 'set'

root = File.expand_path('..', __dir__)
demand = CSV.read(File.join(root, 'docs/audits/data/domscan-whois-registry-demand-2026-10-17.csv'), headers: true)
weights = demand.to_h { |row| [row.fetch('namespace'), Integer(row.fetch('requests'))] }
roots = demand.map { |row| row.fetch('root') }.to_set
legacy = CSV.read(File.join(root, 'docs/audits/data/domscan-whois-first-class-coverage-2026-09-28.csv'), headers: true)
legacy_roots = legacy.select { |row| row['evidence_state'] == 'fixture_pair' }.map { |row| row.fetch('tld') }.to_set - roots
legacy_roots.each { |name| weights[name] = 0 }
allowed_sources = %w[rdap whois cache unknown].freeze
closed = %w[apple dhl google microsoft].freeze
rows = ARGF.each_line.reject { |line| line.strip.empty? }.map { |line| JSON.parse(line) }
raise 'Missing or duplicate namespace observations' unless rows.map { |row| row['namespace'] }.sort == weights.keys.sort
rows.each do |row|
  raise 'Unexpected observation fields' unless row.keys.sort == %w[checks checked_on evidence_set namespace production_build requests].sort
  raise 'Unpinned demand weight' unless row['requests'] == weights.fetch(row['namespace'])
  raise 'Invalid observation date' unless row['checked_on'] == '2026-10-18'
  raise 'Invalid production build' unless row['production_build'].nil? || row['production_build'].match?(/\A[0-9a-f]{40}\z/)
  raise 'Invalid evidence label' unless row['evidence_set'].match?(/\A[a-z0-9_]+\z/)
  raise 'Invalid checks' unless row['checks'].is_a?(Array) && row['checks'].length <= 2
  row['checks'].each_with_index do |check, index|
    raise 'Unexpected check fields' unless check.keys.sort == %w[available expected_registered http registered source].sort
    raise 'Invalid check order' unless check['expected_registered'] == index.zero?
    raise 'Invalid result type' unless [nil, true, false].include?(check['registered']) && [nil, true, false].include?(check['available'])
    raise 'Invalid HTTP status' unless check['http'].nil? || check['http'].is_a?(Integer) && (100..599).cover?(check['http'])
    raise 'Invalid evidence source' unless allowed_sources.include?(check['source'])
  end
end

columns = %w[namespace scope requests registered_source absence_source pair_verified evidence_set checked_on production_build]
CSV($stdout) do |csv|
  csv << columns
  rows.sort_by { |row| [-row['requests'], row['namespace']] }.each do |row|
    positive, negative = row['checks']
    verified = positive && negative && positive['http'] == 200 && negative['http'] == 200 &&
      positive['registered'] == true && positive['available'] != true && negative['registered'] == false &&
      %w[rdap whois].include?(positive['source']) && %w[rdap whois].include?(negative['source']) &&
      negative['available'] == !closed.include?(row['namespace'])
    csv << [row['namespace'], row['requests'].zero? ? 'zero_demand_legacy' : 'usage', row['requests'],
            positive && positive['source'], negative && negative['source'], !!verified,
            row['evidence_set'], row['checked_on'], row['production_build']]
  end
end
