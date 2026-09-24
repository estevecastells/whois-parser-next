require 'spec_helper'
require 'csv'
require 'digest'

RSpec.describe Whois::Parser, 'ICANN DNS Magnitude audit manifest' do
  let(:manifest_path) do
    File.expand_path('../../../docs/audits/data/icann-dns-magnitude-20260912-ranks-1-1000.csv', __dir__)
  end

  let(:manifest_rows) do
    CSV.read(manifest_path, headers: true).map do |row|
      [Integer(row.fetch('source_rank')), row.fetch('tld'), row.fetch('status')]
    end
  end

  let(:audit_reports) do
    %w[
    top-100-tlds-2026-09-19.md
    top-101-125-tlds-2026-09-19.md
    top-126-150-tlds-2026-09-19.md
    topdomains-151-175-2026-09-19.md
    top-176-200-tlds-2026-09-19.md
    top-201-225-tlds-2026-09-19.md
    topdomains-226-250-2026-09-19.md
    topdomains-251-275-2026-09-19.md
    topdomains-276-300-2026-09-19.md
    ]
  end

  # SHA-256 of "source-rank:tld\n" for source ranks 1-1000 from the ICANN
  # DNS Magnitude snapshot dated 2026-09-12 and generated 2026-09-18.
  let(:snapshot_sha256) { '6f1411e1323ed09683480b47314188c71c19d62979d2d7cc2894669b4dd9e681' }

  # The existing audit reports independently pin the first 300 source rows.
  let(:snapshot_1_300_sha256) { '3f30997fd02e9481a316f2eaee541143b16cb445198cbf35956f5ae1c5950b62' }

  def canonical(rows)
    "#{rows.map { |rank, tld, _status| "#{rank}:#{tld}" }.join("\n")}\n"
  end

  def audit_rows
    audit_reports.flat_map do |filename|
      path = File.expand_path("../../../docs/audits/#{filename}", __dir__)

      File.readlines(path).filter_map do |line|
        match = line.match(/^\|\s*(\d+)\s*\|\s*`\.([^`]+)`\s*\|/)
        [match[1].to_i, match[2]] if match
      end
    end
  end

  it 'pins one exact, non-overlapping source row for every rank through 1000' do
    rows = manifest_rows

    expect(rows.map(&:first)).to eq((1..1000).to_a)
    expect(rows.map { |row| row[1] }.uniq.length).to eq(1000)
    expect(rows.map(&:last).uniq).to match_array(%w[delegated special-use undelegated])
    expect(Digest::SHA256.hexdigest(canonical(rows))).to eq(snapshot_sha256)
  end

  it 'keeps the exact existing, non-overlapping source rows through 300' do
    rows = audit_rows.sort_by(&:first)

    expect(rows.map(&:first)).to eq((1..300).to_a)
    expect(rows.map(&:last).uniq.length).to eq(300)
    expect(rows).to eq(manifest_rows.first(300).map { |rank, tld, _status| [rank, tld] })
    expect(Digest::SHA256.hexdigest(canonical(rows))).to eq(snapshot_1_300_sha256)
  end
end
