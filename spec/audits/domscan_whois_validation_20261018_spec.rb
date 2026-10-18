require 'spec_helper'
require 'csv'
require 'json'
require 'open3'
require 'rbconfig'

describe 'DomScan 2026-10-18 production capability evidence' do
  let(:root) { File.expand_path('../..', __dir__) }
  let(:data) { File.join(root, 'docs/audits/data') }
  let(:jsonl) { File.read(File.join(data, 'domscan-whois-production-validation-2026-10-18.jsonl')) }
  let(:observations) { jsonl.lines.map { |line| JSON.parse(line) } }
  let(:builder) { File.join(root, 'scripts/build_domscan_whois_validation_csv.rb') }

  def generate(input)
    Open3.capture3(RbConfig.ruby, builder, stdin_data: input)
  end

  it 'reproduces the dated CSV from strict privacy-safe observations' do
    output, error, status = generate(jsonl)
    expect(status.success?).to eq(true), error
    expect(output).to eq(File.read(File.join(data, 'domscan-whois-production-validation-2026-10-18.csv')))
    rows = CSV.parse(output, headers: true)
    usage = rows.select { |row| row['scope'] == 'usage' }
    expect(usage.length).to eq(342)
    expect(usage.sum { |row| Integer(row['requests']) }).to eq(23_705)
    expect(rows.count { |row| row['scope'] == 'zero_demand_legacy' }).to eq(13)
    expect(usage.find { |row| row['namespace'] == 'org.au' }['requests']).to eq('3')
  end

  it 'rejects duplicate namespaces, modified weights, and unexpected private fields' do
    duplicate = observations + [observations.first]
    wrong_weight = Marshal.load(Marshal.dump(observations))
    wrong_weight.first['requests'] += 1
    private_field = Marshal.load(Marshal.dump(observations))
    private_field.first['raw_whois'] = 'must never be exported'
    [duplicate, wrong_weight, private_field].each do |rows|
      output, _error, status = generate(rows.map { |row| JSON.generate(row) }.join("\n"))
      expect(status.success?).to eq(false)
      expect(output).to eq('')
    end
  end

  it 'excludes blocked, cached, heuristic, contradictory, and unpaired outcomes' do
    [403, 429, 504].each do |http|
      rows = Marshal.load(Marshal.dump(observations))
      row = rows.find { |item| item['namespace'] == 'com' }
      row['checks'] = [
        { 'expected_registered' => true, 'http' => http, 'registered' => true, 'available' => false, 'source' => 'rdap' },
        { 'expected_registered' => false, 'http' => 200, 'registered' => false, 'available' => true, 'source' => 'rdap' }
      ]
      output, error, status = generate(rows.map { |item| JSON.generate(item) }.join("\n"))
      expect(status.success?).to eq(true), error
      expect(CSV.parse(output, headers: true).find { |item| item['namespace'] == 'com' }['pair_verified']).to eq('false')
    end
    ['cache', 'unknown'].each do |source|
      rows = Marshal.load(Marshal.dump(observations))
      rows.find { |item| item['namespace'] == 'com' }['checks'].each { |check| check['source'] = source }
      output, error, status = generate(rows.map { |item| JSON.generate(item) }.join("\n"))
      expect(status.success?).to eq(true), error
      expect(CSV.parse(output, headers: true).find { |item| item['namespace'] == 'com' }['pair_verified']).to eq('false')
    end
  end
end
