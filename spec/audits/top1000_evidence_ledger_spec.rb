require 'csv'
require 'spec_helper'
require_relative '../../scripts/build_top1000_evidence_ledger'

RSpec.describe Top1000EvidenceLedger do
  let(:rows) { described_class.build }
  let(:planning) do
    CSV.table(described_class.path(described_class::PLANNING_PATH))
       .to_h { |row| [row[:source_rank].to_i, row[:implementation_package].to_s] }
  end

  it 'validates the pinned source-rank sequence and digest' do
    source_rows = described_class.manifest_rows

    expect(source_rows.map { |row| row.fetch('source_rank') }).to eq((1..1000).to_a)
  end

  it 'reproduces only row-traceable pairs and package-level detail gaps' do
    pairs = rows.select do |row|
      row.fetch('source_rank') > 100 && row.fetch('evidence_state') == 'paired'
    end
    range_pairs = pairs.group_by do |row|
      row.fetch('source_rank') <= 300 ? '101-300' : '301-1000'
    end.transform_values(&:length)
    package_pairs = pairs.select { |row| row.fetch('source_rank') > 300 }
                         .group_by { |row| planning.fetch(row.fetch('source_rank')) }
                         .transform_values(&:length)
    insufficient = rows.select { |row| row.fetch('evidence_state') == 'report_detail_insufficient' }

    expect(pairs.length).to eq(130)
    expect(range_pairs).to eq('101-300' => 61, '301-1000' => 69)
    expect(package_pairs).to eq(
      'package-1' => 7,
      'package-3' => 1,
      'package-4' => 22,
      'package-5' => 39
    )
    expect(insufficient.length).to eq(31)
    expect(insufficient.map { |row| planning.fetch(row.fetch('source_rank')) }.uniq)
      .to eq(['package-3'])
    package3_rows = rows.select do |row|
      row.fetch('source_rank') > 300 && planning.fetch(row.fetch('source_rank')) == 'package-3'
    end
    package3_states = package3_rows.group_by { |row| row.fetch('evidence_state') }
                                   .transform_values(&:length)
    package4_rows = rows.select do |row|
      row.fetch('source_rank') > 300 && planning.fetch(row.fetch('source_rank')) == 'package-4'
    end
    package4_states = package4_rows.group_by { |row| row.fetch('evidence_state') }
                                   .transform_values(&:length)
    expect(package3_states.values_at('paired', 'report_detail_insufficient', 'absence_only'))
      .to eq([1, 31, 2])
    expect(package4_states.values_at('paired', 'absence_only', 'rdap_only'))
      .to eq([22, 8, 1])
    expect(pairs.find { |row| row.fetch('source_rank') == 729 }.fetch('tld')).to eq('aw')
  end

  it 'keeps Top-100 summary labels distinct from row-level paired evidence' do
    top100 = rows.select { |row| row.fetch('source_rank') <= 100 }
    states = top100.group_by { |row| row.fetch('evidence_state') }.transform_values(&:length)

    expect(top100.length).to eq(100)
    expect(states).to eq(
      'summary_only_healthy_fixed' => 76,
      'summary_only_unsupported' => 6,
      'classification_only' => 6,
      'unknown_unsafe' => 11,
      'registered_only' => 1
    )
    expect(top100.none? { |row| row.fetch('evidence_state') == 'paired' }).to be(true)
  end

  it 'records later .top, .uz, .sa, and .cam pairs separately from baseline evidence' do
    follow_ups = rows.select { |row| row.fetch('follow_up_state') == 'paired' }

    expect(follow_ups.map { |row| [row.fetch('source_rank'), row.fetch('tld')] })
      .to eq([[103, 'top'], [104, 'uz'], [105, 'sa'], [315, 'cam']])
    expect(follow_ups.map { |row| row.fetch('evidence_state') }.uniq)
      .to eq(['registered_only', 'report_detail_insufficient'])
    expect(described_class.hand_audited_subset.length).to eq(264)
  end
end
