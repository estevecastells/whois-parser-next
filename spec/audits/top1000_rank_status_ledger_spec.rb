require 'csv'
require 'digest'
require 'tempfile'
require 'spec_helper'
require_relative '../../scripts/build_top1000_rank_status_ledger'

RSpec.describe Top1000RankStatusLedger do
  let(:rows) { described_class.build }
  let(:rows_by_rank) { rows.to_h { |row| [row.fetch('source_rank'), row] } }

  it 'covers the pinned manifest exactly and retains provenance on every rank' do
    manifest = Top1000EvidenceLedger.manifest_rows

    expect(rows.map { |row| row.fetch('source_rank') }).to eq((1..1000).to_a)
    expect(rows.map { |row| [row.fetch('source_rank'), row.fetch('tld'), row.fetch('source_status')] })
      .to eq(manifest.map { |row| [row.fetch('source_rank'), row.fetch('tld'), row.fetch('source_status')] })
    expect(rows.all? do |row|
      File.file?(described_class.path(row.fetch('report_ref'))) &&
        !row.fetch('evidence_note').to_s.empty?
    end).to be(true)
    expect(rows.all? { |row| described_class::STATUS_STATES.include?(row.fetch('evidence_state')) }).to be(true)
  end

  it 'normalizes summaries and generic verified labels to unknown without losing their source detail' do
    source_rows = Top1000EvidenceLedger.build.to_h { |row| [row.fetch('source_rank'), row] }
    generic_ranks = source_rows.values
                               .select { |row| row.fetch('evidence_state') == 'report_detail_insufficient' }
                               .map { |row| row.fetch('source_rank') }

    expect(generic_ranks.length).to eq(31)
    expect(rows.select { |row| generic_ranks.include?(row.fetch('source_rank')) }
               .all? { |row| row.fetch('evidence_state') == 'unknown' }).to be(true)

    expect(rows_by_rank.fetch(1).values_at('evidence_state', 'evidence_note')).to eq(['unknown', 'Healthy'])
    expect(rows_by_rank.fetch(6).values_at('evidence_state', 'evidence_note')).to eq(['unknown', 'Unsupported'])
    generic_rank = generic_ranks.first
    expect(rows_by_rank.fetch(generic_rank).fetch('evidence_note'))
      .to eq(source_rows.fetch(generic_rank).fetch('evidence_note'))
    expect(rows_by_rank.fetch(generic_rank).fetch('report_ref'))
      .to eq(source_rows.fetch(generic_rank).fetch('report_ref'))
    expect(rows_by_rank.fetch(607).fetch('evidence_state')).to eq('unknown')
    expect(rows_by_rank.fetch(840).fetch('evidence_state')).to eq('unknown')
    expect(rows_by_rank.fetch(457).fetch('evidence_state')).to eq('unknown')
  end

  it 'keeps unsupported only when a rank-specific report records the exact denial' do
    unsupported = rows.select { |row| row.fetch('evidence_state') == 'explicit_unsupported' }

    expect(unsupported.length).to eq(205)
    expect(unsupported.all? do |row|
      row.fetch('fixture_scope') == 'report_collection' &&
        !row.fetch('fixture_ref').empty? &&
        described_class.reported_exact_unsupported_denial?(row)
    end).to be(true)
    expect(described_class.normalize_state(
      'evidence_state' => 'explicit_unsupported',
      'source_rank' => 1,
      'fixture_scope' => 'not_reported',
      'fixture_ref' => '',
      'evidence_note' => 'Unsupported'
    )).to eq('unknown')
    expect(described_class.normalize_state(rows_by_rank.fetch(457).merge('evidence_state' => 'explicit_unsupported')))
      .to eq('unknown')
  end

  it 'uses only explicit source classifications for classification-only status' do
    classification_only = rows.select { |row| row.fetch('evidence_state') == 'classification_only' }

    expect(classification_only.length).to eq(157)
    expect(classification_only.all? do |row|
      %w[undelegated special-use].include?(row.fetch('source_status')) ||
        row.fetch('evidence_note') == 'Infrastructure; excluded from registrable-domain parser scope'
    end).to be(true)
    expect(rows_by_rank.fetch(4).fetch('evidence_state')).to eq('classification_only')
    expect(rows_by_rank.fetch(326).fetch('evidence_state')).to eq('unknown')
    expect(rows_by_rank.fetch(493).fetch('evidence_state')).to eq('unknown')
    expect(described_class.normalize_state(
      'evidence_state' => 'classification_only',
      'source_rank' => 1,
      'source_status' => 'delegated',
      'evidence_note' => 'No port-43 parser'
    )).to eq('unknown')
    expect(described_class.normalize_state(
      'evidence_state' => 'classification_only',
      'source_rank' => 1,
      'source_status' => 'undelegated',
      'evidence_note' => 'No parser'
    )).to eq('classification_only')
  end

  it 'preserves the 130 pinned rank-101+ pairs and keeps later observations separate' do
    pairs = rows.select do |row|
      row.fetch('source_rank') > 100 && row.fetch('evidence_state') == 'paired'
    end
    pair_digest = Digest::SHA256.hexdigest(
      pairs.map { |row| "#{row.fetch('source_rank')}:#{row.fetch('tld')}\n" }.join
    )

    expect(pairs.length).to eq(130)
    expect(pair_digest).to eq(described_class::PINNED_PAIR_RANK_TLD_SHA256)
    expect(rows_by_rank.fetch(24).values_at('evidence_state', 'follow_up_state'))
      .to eq(['unknown', 'registered_only'])
    expect(rows_by_rank.fetch(103).values_at('evidence_state', 'follow_up_state'))
      .to eq(['registered_only', 'paired'])
    expect(rows_by_rank.fetch(104).values_at('evidence_state', 'follow_up_state'))
      .to eq(['registered_only', 'paired'])
    expect(rows_by_rank.fetch(105).values_at('evidence_state', 'follow_up_state'))
      .to eq(['registered_only', 'paired'])
    expect(rows_by_rank.fetch(122).values_at('evidence_state', 'follow_up_state'))
      .to eq(['unknown', 'paired'])
    expect(rows_by_rank.fetch(203).values_at('evidence_state', 'follow_up_state'))
      .to eq(['unknown', 'paired'])
    expect(rows.count { |row| !row.fetch('follow_up_state').empty? }).to eq(18)
  end

  it 'writes a reproducible 1,000-row CSV artifact' do
    expected = described_class.render

    Tempfile.create('whois-parser-top1000-rank-status-ledger') do |file|
      expect(described_class.write(file.path)).to eq(1000)
      expect(File.read(file.path)).to eq(expected)

      csv_rows = CSV.read(file.path, headers: true)
      expect(csv_rows.length).to eq(1000)
      expect(csv_rows.first['source_rank']).to eq('1')
      expect(csv_rows[-1]['source_rank']).to eq('1000')
    end
  end

  it 'keeps the checked-in artifact in sync with the generator' do
    artifact = described_class.path(described_class::OUTPUT_PATH)

    expect(File.read(artifact)).to eq(described_class.render)
  end
end
