#!/usr/bin/env ruby

require 'csv'
require 'digest'
require_relative 'build_top1000_evidence_ledger'

module Top1000RankStatusLedger
  ROOT = File.expand_path('..', __dir__)
  OUTPUT_PATH = 'docs/audits/data/whois-parser-top1000-rank-status-ledger-2026-09-25.csv'.freeze
  HEADERS = Top1000EvidenceLedger::HEADERS
  STATUS_STATES = %w[
    paired registered_only absence_only explicit_unsupported rdap_only
    classification_only unknown
  ].freeze
  UNKNOWN_SOURCE_STATES = %w[
    unknown_unsafe summary_only_healthy_fixed summary_only_unsupported
    report_detail_insufficient
  ].freeze
  REPORTED_UNSUPPORTED_CLAIM = /(?:TLD (?:is )?not supported|Tld not supported|TLD[- ]not[- ]supported response|explicit unsupported[- ]TLD denial|explicit registry denial)/i
  SOURCE_CLASSIFICATION_STATUSES = %w[undelegated special-use].freeze
  PINNED_PAIR_COUNT = 130
  PINNED_PAIR_RANK_TLD_SHA256 = '5dcc6fa13df956c6456b6633c49b1c63d91aa5c83230d9a952a557d70d075896'.freeze

  FOLLOW_UPS = {
    24 => {
      'follow_up_state' => 'registered_only',
      'follow_up_date' => '2026-09-25',
      'follow_up_report_ref' => 'docs/audits/top-us-current-2026-09-25.md',
      'follow_up_fixture_ref' => 'spec/fixtures/responses/whois.nic.us/us/status_registered_current.txt;spec/fixtures/responses/whois.nic.us/us/status_no_record_current.txt',
      'follow_up_note' => 'A registered record was observed. The generated-name reply was No Data Found, which the registry disclaimer says does not indicate availability.',
    },
    33 => {
      'follow_up_state' => 'unknown',
      'follow_up_date' => '2026-09-25',
      'follow_up_report_ref' => 'docs/audits/top-1000-effective-coverage-scorecard-2026-09-25.md',
      'follow_up_note' => 'The current response denied this client access. Denial does not establish registration or absence.',
    },
    43 => {
      'follow_up_state' => 'rdap_only_no_whois',
      'follow_up_date' => '2026-09-25',
      'follow_up_report_ref' => 'docs/audits/top1000-es-pk-shop-dev-app-2026-09-25.md',
      'follow_up_note' => 'IANA lists Google Registry RDAP and no WHOIS server; no WHOIS result is inferred.',
    },
    47 => {
      'follow_up_state' => 'rdap_only_no_whois',
      'follow_up_date' => '2026-09-25',
      'follow_up_report_ref' => 'docs/audits/top1000-es-pk-shop-dev-app-2026-09-25.md',
      'follow_up_note' => 'IANA lists Google Registry RDAP and no WHOIS server; no WHOIS result is inferred.',
    },
    52 => {
      'follow_up_state' => 'unknown',
      'follow_up_date' => '2026-09-25',
      'follow_up_report_ref' => 'docs/audits/top1000-es-pk-shop-dev-app-2026-09-25.md',
      'follow_up_note' => 'The registry limits port-43 access to approved IP addresses; no unauthorized query was attempted and no WHOIS result is inferred.',
    },
    84 => {
      'follow_up_state' => 'port43_parser_pair_not_standard_route',
      'follow_up_date' => '2026-09-25',
      'follow_up_report_ref' => 'docs/audits/top1000-es-pk-shop-dev-app-2026-09-25.md',
      'follow_up_fixture_ref' => 'spec/fixtures/responses/whois.pknic.net.pk',
      'follow_up_note' => 'Registered and explicit-availability response evidence exists at PKNIC, but the standard whois client selects a legacy web adapter for .pk.',
    },
    103 => {
      'follow_up_state' => 'paired',
      'follow_up_date' => '2026-09-25',
      'follow_up_report_ref' => 'docs/audits/top-us-current-2026-09-25.md',
      'follow_up_fixture_ref' => 'spec/fixtures/responses/whois.nic.top/top/status_registered_current.txt;spec/fixtures/responses/whois.nic.top/top/status_absent_current.txt',
      'follow_up_note' => 'A later bounded report records registered and exact authoritative absence evidence; the pinned row remains registered-only.',
    },
    104 => {
      'follow_up_state' => 'paired',
      'follow_up_date' => '2026-09-25',
      'follow_up_report_ref' => 'docs/audits/top-101-125-tlds-2026-09-19.md',
      'follow_up_fixture_ref' => 'spec/fixtures/responses/audit_20260925_ranks104_105',
      'follow_up_note' => 'A later bounded report adds registered and exact generated-name no-entry evidence; the pinned row remains registered-only.',
    },
    105 => {
      'follow_up_state' => 'paired',
      'follow_up_date' => '2026-09-25',
      'follow_up_report_ref' => 'docs/audits/top-101-125-tlds-2026-09-19.md',
      'follow_up_fixture_ref' => 'spec/fixtures/responses/audit_20260925_ranks104_105',
      'follow_up_note' => 'A later bounded report adds registered and exact generated-name no-match evidence; the pinned row remains registered-only.',
    },
    122 => {
      'follow_up_state' => 'paired',
      'follow_up_date' => '2026-09-25',
      'follow_up_report_ref' => 'docs/audits/top-101-125-tlds-2026-09-19.md',
      'follow_up_fixture_ref' => 'spec/fixtures/responses/audit_20260925_rank122_ge/whois.nic.ge',
      'follow_up_note' => 'A later pair was captured from IANA-listed whois.nic.ge. The default whois client still routes .ge to whois.registration.ge, so the pair does not establish default-route coverage.',
    },
    129 => {
      'follow_up_state' => 'paired',
      'follow_up_date' => '2026-09-25',
      'follow_up_report_ref' => 'docs/audits/top-126-150-tlds-2026-09-19.md',
      'follow_up_fixture_ref' => 'spec/fixtures/responses/audit_20260925_rank129_hn/whois.nic.hn',
      'follow_up_note' => 'A later report adds a registered response to the earlier no-object observation; current denial and ambiguous cases remain unknown.',
    },
    131 => {
      'follow_up_state' => 'paired',
      'follow_up_date' => '2026-09-25',
      'follow_up_report_ref' => 'docs/audits/top-126-150-tlds-2026-09-19.md',
      'follow_up_fixture_ref' => 'spec/fixtures/responses/audit_20260925_rank131_ma/whois.registre.ma',
      'follow_up_note' => 'A later bounded report records registered and exact no-object evidence at whois.registre.ma; denied, throttled, and ambiguous replies remain unknown.',
    },
    157 => {
      'follow_up_state' => 'rdap_only_no_whois',
      'follow_up_date' => '2026-09-25',
      'follow_up_report_ref' => 'docs/audits/top1000-es-pk-shop-dev-app-2026-09-25.md',
      'follow_up_note' => 'The legacy WHOIS endpoint returns a retirement notice; current service evidence is through the official RDAP endpoint.',
    },
    201 => {
      'follow_up_state' => 'unknown',
      'follow_up_date' => '2026-09-25',
      'follow_up_report_ref' => 'docs/audits/top-201-250-current-host-followup-2026-09-25.md',
      'follow_up_note' => 'The IANA-listed whois.cmc.iq host did not resolve from the audit environment; no parser classification is supported.',
    },
    203 => {
      'follow_up_state' => 'paired',
      'follow_up_date' => '2026-09-25',
      'follow_up_report_ref' => 'docs/audits/top-201-250-current-host-followup-2026-09-25.md',
      'follow_up_fixture_ref' => 'spec/fixtures/responses/topdomains_201_250_current_20260925/whois.tld.mu',
      'follow_up_note' => 'A registered and generated-name pair was captured from IANA-listed whois.tld.mu. The standard whois client routes .mu elsewhere, so this does not establish default-route coverage.',
    },
    205 => {
      'follow_up_state' => 'unknown',
      'follow_up_date' => '2026-09-25',
      'follow_up_report_ref' => 'docs/audits/top-201-250-current-host-followup-2026-09-25.md',
      'follow_up_note' => 'IANA lists no WHOIS endpoint for .ga and the mapped host did not resolve; no WHOIS classification is inferred.',
    },
    212 => {
      'follow_up_state' => 'paired',
      'follow_up_date' => '2026-09-25',
      'follow_up_report_ref' => 'docs/audits/top-201-250-current-host-followup-2026-09-25.md',
      'follow_up_fixture_ref' => 'spec/fixtures/responses/topdomains_201_250_current_20260925/whois.nic.africa',
      'follow_up_note' => 'A registered and generated-name pair was captured from IANA-listed whois.nic.africa. The standard whois client routes .africa elsewhere, so this does not establish default-route coverage.',
    },
    251 => {
      'follow_up_state' => 'paired',
      'follow_up_date' => '2026-09-25',
      'follow_up_report_ref' => 'docs/audits/topdomains-251-275-sr-followup-2026-09-25.md',
      'follow_up_fixture_ref' => 'spec/fixtures/responses/topdomains_251_275/whois.sr',
      'follow_up_note' => 'A registered and generated-name pair was captured from IANA-listed whois.sr. The standard client has no .sr route, so this does not establish default-route coverage.',
    },
    315 => {
      'follow_up_state' => 'observed_pair_unreplayable',
      'follow_up_date' => '2026-09-25',
      'follow_up_report_ref' => 'docs/audits/top1000-rank315-cam-followup-2026-09-25.md',
      'follow_up_fixture_ref' => '',
      'follow_up_note' => 'Point-in-time registered and authoritative-absence responses were observed, but terms prevent retaining exact response fixtures; hashes cannot replay or independently validate parsing; pinned baseline remains unchanged.',
    },
  }.freeze

  def self.path(relative_path)
    File.join(ROOT, relative_path)
  end

  def self.require_file(relative_path)
    raise "Missing evidence artifact: #{relative_path}" unless File.file?(path(relative_path))
  end

  def self.normalize_state(row)
    state = row.fetch('evidence_state')
    return 'unknown' if UNKNOWN_SOURCE_STATES.include?(state)

    if state == 'explicit_unsupported'
      return 'explicit_unsupported' if reported_exact_unsupported_denial?(row)

      return 'unknown'
    end
    if state == 'classification_only'
      return 'classification_only' if source_classification?(row)

      return 'unknown'
    end
    return state if STATUS_STATES.include?(state)

    raise "Cannot normalize evidence state #{state.inspect} at rank #{row['source_rank']}"
  end

  def self.reported_exact_unsupported_denial?(row)
    return false unless row.fetch('fixture_scope') == 'report_collection'
    return false if row.fetch('fixture_ref').to_s.empty?

    report_rows = Top1000EvidenceLedger.markdown_table_rows(row.fetch('report_ref'))
    row_specific_report = report_rows.any? do |report_row|
      report_row.fetch('source_rank') == row.fetch('source_rank') && report_row.fetch('tld') == row.fetch('tld')
    end
    row_specific_report && row.fetch('evidence_note').match?(REPORTED_UNSUPPORTED_CLAIM)
  end

  def self.source_classification?(row)
    return true if SOURCE_CLASSIFICATION_STATUSES.include?(row.fetch('source_status'))

    row.fetch('evidence_note').match?(/\AInfrastructure; excluded from registrable-domain parser scope\z/i)
  end

  def self.restore_us_baseline!(row)
    return unless row.fetch('source_rank') == 24

    entry = Top1000EvidenceLedger.markdown_table_rows(Top1000EvidenceLedger::TOP100_PATH)
                                 .find { |item| item.fetch('source_rank') == 24 }
    raise 'Missing rank-24 Top-100 source row' unless entry

    label = entry.fetch('cells')[2].to_s.gsub('`', '').strip
    row['evidence_state'] = 'unknown'
    row['evidence_date'] = Top1000EvidenceLedger.report_date(Top1000EvidenceLedger::TOP100_PATH)
    row['report_ref'] = Top1000EvidenceLedger::TOP100_PATH
    row['fixture_ref'] = ''
    row['fixture_scope'] = 'not_reported'
    row['evidence_note'] = "#{label} (Top-100 summary label only)"
  end

  def self.apply_follow_ups!(row)
    FOLLOW_UPS.fetch(row.fetch('source_rank'), {}).each do |field, value|
      row[field] = value
    end
  end

  def self.validate_fixture_reference!(fixture_ref, scope, context)
    paths = fixture_ref.to_s.split(';').reject(&:empty?)
    if paths.empty?
      raise "Unexpected fixture path for #{context}" unless %w[not_reported].include?(scope)

      return
    end

    paths.each do |relative_path|
      artifact_path = path(relative_path)
      valid = if scope == 'report_collection'
                File.directory?(artifact_path)
              else
                File.file?(artifact_path) || File.directory?(artifact_path)
              end
      raise "Missing fixture provenance #{relative_path} for #{context}" unless valid
    end
  end

  def self.validate!(rows, source_rows)
    ranks = rows.map { |row| row.fetch('source_rank') }
    raise 'Ledger must contain ranks 1-1000 exactly once' unless ranks == (1..1000).to_a

    source_by_rank = source_rows.to_h { |row| [row.fetch('source_rank'), row] }
    rows.each do |row|
      source = source_by_rank.fetch(row.fetch('source_rank'))
      unless row.fetch('tld') == source.fetch('tld') && row.fetch('source_status') == source.fetch('source_status')
        raise "Manifest mismatch at rank #{row['source_rank']}"
      end
      raise "Invalid normalized state at rank #{row['source_rank']}" unless STATUS_STATES.include?(row.fetch('evidence_state'))
      raise "Missing evidence report at rank #{row['source_rank']}" if row.fetch('report_ref').to_s.empty?

      require_file(row.fetch('report_ref'))
      raise "Missing baseline evidence note at rank #{row['source_rank']}" if row.fetch('evidence_note').to_s.empty?

      validate_fixture_reference!(row.fetch('fixture_ref'), row.fetch('fixture_scope'), "rank #{row['source_rank']}")

      follow_up_state = row.fetch('follow_up_state').to_s
      next if follow_up_state.empty?

      raise "Incomplete follow-up provenance at rank #{row['source_rank']}" if
        row.fetch('follow_up_date').to_s.empty? || row.fetch('follow_up_report_ref').to_s.empty? || row.fetch('follow_up_note').to_s.empty?

      require_file(row.fetch('follow_up_report_ref'))
      validate_fixture_reference!(row.fetch('follow_up_fixture_ref'), 'row_specific', "rank #{row['source_rank']} follow-up") unless row.fetch('follow_up_fixture_ref').to_s.empty?
    end

    pairs = rows.select { |row| row.fetch('source_rank') > 100 && row.fetch('evidence_state') == 'paired' }
    pair_digest = Digest::SHA256.hexdigest(
      pairs.map { |row| "#{row.fetch('source_rank')}:#{row.fetch('tld')}\n" }.join
    )
    unless pairs.length == PINNED_PAIR_COUNT && pair_digest == PINNED_PAIR_RANK_TLD_SHA256
      raise "Pinned pair audit changed: count=#{pairs.length} digest=#{pair_digest}"
    end

    rows
  end

  def self.build
    source_rows = Top1000EvidenceLedger.manifest_rows
    evidence_by_rank = Top1000EvidenceLedger.build.to_h { |row| [row.fetch('source_rank'), row] }

    rows = source_rows.map do |source|
      rank = source.fetch('source_rank')
      row = evidence_by_rank.fetch(rank).dup
      unless row.fetch('tld') == source.fetch('tld') && row.fetch('source_status') == source.fetch('source_status')
        raise "Evidence crosswalk does not match the pinned manifest at rank #{rank}"
      end

      row['evidence_state'] = normalize_state(row)
      restore_us_baseline!(row)
      apply_follow_ups!(row)
      row
    end

    validate!(rows, source_rows)
  end

  def self.render(rows = build)
    CSV.generate do |csv|
      csv << HEADERS
      rows.each { |row| csv << HEADERS.map { |header| row[header] } }
    end
  end

  def self.write(output_path = path(OUTPUT_PATH))
    rows = build
    File.write(output_path, render(rows))
    rows.length
  end
end

if $PROGRAM_NAME == __FILE__
  output = ARGV.fetch(0, Top1000RankStatusLedger.path(Top1000RankStatusLedger::OUTPUT_PATH))
  puts "wrote #{Top1000RankStatusLedger.write(output)} rows to #{output}"
end
