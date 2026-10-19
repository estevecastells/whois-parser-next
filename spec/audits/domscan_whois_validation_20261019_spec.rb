require 'spec_helper'
require 'csv'
require 'json'
require 'open3'
require 'rbconfig'

describe 'DomScan 2026-10-19 remaining-namespace follow-up' do
  let(:root) { File.expand_path('../..', __dir__) }
  let(:data) { File.join(root, 'docs/audits/data') }

  it 'reproduces the private-data-free follow-up without altering the pinned baseline' do
    stem = File.join(data, 'domscan-whois-production-validation-2026-10-19')
    input = File.read("#{stem}.jsonl")
    output, error, status = Open3.capture3(RbConfig.ruby,
      File.join(root, 'scripts/build_domscan_whois_validation_csv.rb'), stdin_data: input)
    expect(status.success?).to eq(true), error
    expect(output).to eq(File.read("#{stem}.csv"))
    rows = CSV.parse(output, headers: true)
    verified = rows.select { |row| row['pair_verified'] == 'true' }
    usage = verified.select { |row| row['scope'] == 'usage' }
    expect(rows.length).to eq(355)
    expect(verified.length).to eq(315)
    expect(verified.map { |row| row['namespace'].split('.').last }.uniq.length).to eq(282)
    expect(usage.length).to eq(302)
    expect(usage.sum { |row| Integer(row['requests']) }).to eq(23_479)
    unresolved = rows.reject { |row| row['pair_verified'] == 'true' }
    expect(unresolved.length).to eq(40)
    expect(unresolved.sum { |row| Integer(row['requests']) }).to eq(226)
    baseline = CSV.read(File.join(data, 'domscan-whois-production-validation-2026-10-18.csv'), headers: true)
    changed = rows.select do |row|
      old = baseline.find { |item| item['namespace'] == row['namespace'] }
      row['pair_verified'] != old['pair_verified']
    end
    expect(changed.map { |row| row['namespace'] }.sort).to eq(%w[com.gt ga gt jo mw sx])
    expect(rows.select { |row| %w[ph es mt il].include?(row['namespace']) }.map { |row| row['pair_verified'] }.uniq).to eq(['false'])
  end
end
