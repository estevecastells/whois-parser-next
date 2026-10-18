require 'spec_helper'
require 'csv'

describe 'DomScan 2026-10-17 request evidence' do
  let(:data) { File.expand_path('../../docs/audits/data', __dir__) }

  it 'retains the complete suffix aggregate without treating HTTP success as parser coverage' do
    rows = CSV.read(File.join(data, 'domscan-whois-usage-2026-10-17.csv'), headers: true)
    expect(rows.length).to eq(455)
    expect(rows.map { |row| row['tld'] }.uniq.length).to eq(rows.length)
    expect(rows.sum { |row| Integer(row['requests']) }).to eq(24_718)
    expect(rows.sum { |row| Integer(row['traditional_whois_used']) }).to eq(2_822)
    rows.each do |row|
      expect(row['tld']).to match(/\A[a-z0-9-]+\z/)
      row.headers.drop(1).each { |column| expect(Integer(row[column])).to be >= 0 }
      expect(Integer(row['http_200'])).to be <= Integer(row['requests'])
    end
    io = rows.find { |row| row['tld'] == 'io' }
    expect(Integer(io['unknown_or_unretained'])).to eq(818)
  end

  it 'records bounded preview outcomes separately from live validation' do
    rows = CSV.read(File.join(data, 'domscan-whois-replay-2026-10-17.csv'), headers: true)
    expect(rows.headers).to eq(%w[tld recorded_class parser_class preview_state count])
    expect(rows.sum { |row| Integer(row['count']) }).to eq(2_821)
    expect(rows.map { |row| row['tld'] }.uniq.length).to eq(119)
    confirmed = rows.select do |row|
      row['tld'] == 'lu' && row['recorded_class'] == 'available' &&
        row['parser_class'] == 'registered' && row['preview_state'] == 'retained'
    end
    expect(confirmed.sum { |row| Integer(row['count']) }).to eq(741)
    expect(rows.map { |row| row['preview_state'] }.uniq.sort).to eq(%w[possibly_truncated retained])
  end

  it 'retains recorded source counts without counting DNS heuristics as authoritative' do
    rows = CSV.read(File.join(data, 'domscan-whois-sources-2026-10-17.csv'), headers: true)
    counts = rows.group_by { |row| row['source'] }.transform_values do |group|
      group.sum { |row| Integer(row['requests']) }
    end
    expect(counts).to eq('rdap' => 16_835, 'whois' => 2_822, 'cache' => 1_713, 'unknown' => 2_049)
    expect(counts.values.sum).to eq(23_419)
  end
end
