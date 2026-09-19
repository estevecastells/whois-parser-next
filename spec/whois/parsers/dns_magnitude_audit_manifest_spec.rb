require 'spec_helper'
require 'digest'

RSpec.describe Whois::Parser, 'ICANN DNS Magnitude audit manifest' do
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

  # SHA-256 of "source-rank:tld\n" for source ranks 1-300 from the ICANN DNS
  # Magnitude snapshot dated 2026-09-12 and generated 2026-09-18.
  let(:snapshot_sha256) { '3f30997fd02e9481a316f2eaee541143b16cb445198cbf35956f5ae1c5950b62' }

  def audit_rows
    audit_reports.flat_map do |filename|
      path = File.expand_path("../../../docs/audits/#{filename}", __dir__)

      File.readlines(path).filter_map do |line|
        match = line.match(/^\|\s*(\d+)\s*\|\s*`\.([^`]+)`\s*\|/)
        [match[1].to_i, match[2]] if match
      end
    end
  end

  it 'keeps one exact, non-overlapping source row for every rank through 300' do
    rows = audit_rows.sort_by(&:first)
    canonical = "#{rows.map { |rank, tld| "#{rank}:#{tld}" }.join("\n")}\n"

    expect(rows.map(&:first)).to eq((1..300).to_a)
    expect(rows.map(&:last).uniq.length).to eq(300)
    expect(Digest::SHA256.hexdigest(canonical)).to eq(snapshot_sha256)
  end
end
