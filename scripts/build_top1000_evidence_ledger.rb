#!/usr/bin/env ruby

require 'csv'
require 'digest'

module Top1000EvidenceLedger
  ROOT = File.expand_path('..', __dir__)
  SOURCE_PATH = 'docs/audits/data/icann-dns-magnitude-20260912-ranks-1-1000.csv'.freeze
  PLANNING_PATH = 'docs/audits/data/whois-parser-top1000-planning.csv'.freeze
  TOP100_PATH = 'docs/audits/top-100-tlds-2026-09-19.md'.freeze
  PINNED_SHA256 = '6f1411e1323ed09683480b47314188c71c19d62979d2d7cc2894669b4dd9e681'.freeze

  RANGE_REPORTS = {
    'docs/audits/top-101-125-tlds-2026-09-19.md' => 'spec/fixtures/responses/audit_20260919_ranks101_125',
    'docs/audits/top-126-150-tlds-2026-09-19.md' => 'spec/fixtures/responses/audit-126-150-2026-09-19',
    'docs/audits/topdomains-151-175-2026-09-19.md' => 'spec/fixtures/responses/topdomains_151_175',
    'docs/audits/top-176-200-tlds-2026-09-19.md' => 'spec/fixtures/responses/topdomains_176_200',
    'docs/audits/top-201-225-tlds-2026-09-19.md' => 'spec/fixtures/responses/topdomains_201_225',
    'docs/audits/topdomains-226-250-2026-09-19.md' => 'spec/fixtures/responses/topdomains_226_250',
    'docs/audits/topdomains-251-275-2026-09-19.md' => 'spec/fixtures/responses/topdomains_251_275',
    'docs/audits/topdomains-276-300-2026-09-19.md' => 'spec/fixtures/responses/topdomains_276_300',
  }.freeze

  PACKAGE_REPORTS = {
    2 => ['docs/audits/whois-parser-top1000-package-2-2026-09-19.md', 'spec/fixtures/responses/top1000_package_2'],
    3 => ['docs/audits/whois-parser-top1000-package-3-2026-09-19.md', 'spec/fixtures/responses/top1000_package3'],
    4 => ['docs/audits/whois-parser-top1000-package-4-2026-09-19.md', 'spec/fixtures/responses/topdomains_package_4'],
    5 => ['docs/audits/whois-parser-top1000-package-5-2026-09-19.md', 'spec/fixtures/responses/top1000_package5'],
  }.freeze
  PACKAGE_NAMES = %w[package-1 package-2 package-3 package-4 package-5].freeze

  PACKAGE1_REPORT = 'docs/audits/whois-parser-top1000-package-1-2026-09-19.md'.freeze
  PACKAGE1_FIXTURES = 'spec/fixtures/responses/top1000_package1'.freeze
  EVIDENCE_STATES = %w[
    paired
    registered_only
    absence_only
    explicit_unsupported
    rdap_only
    unknown_unsafe
    classification_only
    summary_only_healthy_fixed
    summary_only_unsupported
    report_detail_insufficient
  ].freeze

  HEADERS = %w[
    source_rank tld source_status evidence_state evidence_date report_ref
    fixture_ref fixture_scope evidence_note follow_up_state follow_up_date
    follow_up_report_ref follow_up_fixture_ref follow_up_note
  ].freeze

  FOLLOW_UPS = {
    24 => {
      'evidence_state' => 'registered_only',
      'evidence_date' => '2026-09-25',
      'report_ref' => 'docs/audits/top-us-current-2026-09-25.md',
      'fixture_ref' => 'spec/fixtures/responses/whois.nic.us/us/status_registered_current.txt;spec/fixtures/responses/whois.nic.us/us/status_no_record_current.txt',
      'fixture_scope' => 'row_specific',
      'evidence_note' => 'Registered record observed; No Data Found is non-authoritative under the registry disclaimer.',
    },
    43 => {
      'follow_up_state' => 'rdap_only_no_whois',
      'follow_up_date' => '2026-09-25',
      'follow_up_report_ref' => 'docs/audits/top1000-es-pk-shop-dev-app-2026-09-25.md',
      'follow_up_note' => 'IANA lists Google Registry RDAP and no WHOIS server; no WHOIS parser result is inferred.',
    },
    47 => {
      'follow_up_state' => 'rdap_only_no_whois',
      'follow_up_date' => '2026-09-25',
      'follow_up_report_ref' => 'docs/audits/top1000-es-pk-shop-dev-app-2026-09-25.md',
      'follow_up_note' => 'IANA lists Google Registry RDAP and no WHOIS server; no WHOIS parser result is inferred.',
    },
    84 => {
      'follow_up_state' => 'port43_parser_pair_not_standard_route',
      'follow_up_date' => '2026-09-25',
      'follow_up_report_ref' => 'docs/audits/top1000-es-pk-shop-dev-app-2026-09-25.md',
      'follow_up_fixture_ref' => 'spec/fixtures/responses/whois.pknic.net.pk/pk',
      'follow_up_note' => 'The report documents a registered and explicit-availability pair at PKNIC, but the locked whois client maps .pk to a legacy web adapter.',
    },
    103 => {
      'follow_up_state' => 'paired',
      'follow_up_date' => '2026-09-25',
      'follow_up_report_ref' => 'docs/audits/top-us-current-2026-09-25.md',
      'follow_up_fixture_ref' => 'spec/fixtures/responses/whois.nic.top/top/status_registered_current.txt;spec/fixtures/responses/whois.nic.top/top/status_absent_current.txt',
      'follow_up_note' => 'A later bounded report records registered and exact authoritative absence evidence; the pinned scorecard does not add this follow-up to its counts.',
    },
    104 => {
      'follow_up_state' => 'paired',
      'follow_up_date' => '2026-09-25',
      'follow_up_report_ref' => 'docs/audits/top-101-125-tlds-2026-09-19.md',
      'follow_up_fixture_ref' => 'spec/fixtures/responses/audit_20260925_ranks104_105',
      'follow_up_note' => 'The report adds current registered and exact generated-name no-entry evidence after the scorecard baseline.',
    },
    105 => {
      'follow_up_state' => 'paired',
      'follow_up_date' => '2026-09-25',
      'follow_up_report_ref' => 'docs/audits/top-101-125-tlds-2026-09-19.md',
      'follow_up_fixture_ref' => 'spec/fixtures/responses/audit_20260925_ranks104_105',
      'follow_up_note' => 'The report adds current registered and exact generated-name no-match evidence after the scorecard baseline.',
    },
    315 => {
      'follow_up_state' => 'paired',
      'follow_up_date' => '2026-09-25',
      'follow_up_report_ref' => 'docs/audits/top1000-rank315-cam-followup-2026-09-25.md',
      'follow_up_fixture_ref' => '',
      'follow_up_note' => 'A bounded point-in-time row-specific pair is summarized by sanitized response hashes because CentralNic terms prohibit storing or reproducing service data; the pinned baseline remains unchanged.',
    },
  }.freeze

  def self.path(relative_path)
    File.join(ROOT, relative_path)
  end

  def self.require_file(relative_path)
    raise "Missing evidence artifact: #{relative_path}" unless File.file?(path(relative_path))
  end

  def self.manifest_rows
    require_file(SOURCE_PATH)
    rows = CSV.table(path(SOURCE_PATH)).map do |row|
      {
        'source_rank' => row[:source_rank].to_i,
        'tld' => row[:tld].to_s,
        'source_status' => row[:status].to_s,
      }
    end
    ranks = rows.map { |row| row['source_rank'] }
    raise 'Source manifest must contain ranks 1-1000 exactly once' unless ranks == (1..1000).to_a

    canonical = rows.map { |row| "#{row['source_rank']}:#{row['tld']}\n" }.join
    digest = Digest::SHA256.hexdigest(canonical)
    raise "Pinned source digest mismatch: #{digest}" unless digest == PINNED_SHA256

    rows
  end

  def self.markdown_table_rows(relative_path)
    require_file(relative_path)
    File.readlines(path(relative_path)).each_with_object([]) do |line, rows|
      next unless line =~ /^\|\s*(\d+)\s*\|/

      cells = line.split('|')[1...-1].map(&:strip)
      next if cells.length < 3

      rank = cells[0].to_i
      tld = cells[1].to_s.gsub('`', '').sub(/^\./, '')
      next if tld.empty?

      rows << {
        'source_rank' => rank,
        'tld' => tld,
        'cells' => cells,
        'detail' => cells.drop(2).join(' | ').gsub('`', '').strip,
        'raw' => line.strip,
      }
    end
  end

  def self.report_date(relative_path)
    line = File.readlines(path(relative_path)).find { |item| item =~ /^Date:\s*\d{4}-\d{2}-\d{2}/ }
    line ? line[/\d{4}-\d{2}-\d{2}/] : '2026-09-19'
  end

  def self.fixture_fields(_relative_path, fixture_path)
    if fixture_path && File.directory?(path(fixture_path))
      [fixture_path, 'report_collection']
    else
      ['', 'not_reported']
    end
  end

  def self.summary_state(label)
    value = label.downcase
    return 'classification_only' if value.match?(/special-use|undelegated|infrastructure|web-only|no port-43 parser/)
    return 'summary_only_unsupported' if value.include?('unsupported')
    return 'summary_only_healthy_fixed' if ['healthy', 'fixed'].include?(value)

    'unknown_unsafe'
  end

  def self.classify_detail(detail)
    value = detail.downcase

    return 'classification_only' if value.match?(/undelegated|special-use|web-only|classification only|no port[- ]43|no standard whois|no[_ -]server[_ -]mapping|no server|no whois adapter|no adapter|adapter is none|adapter none|none adapter|no delegation status|no root delegation/)
    return 'rdap_only' if value.match?(/whois.{0,60}retir.{0,60}rdap|rdap[- ]only|rdap.{0,30}retir|retired.{0,30}for rdap/)
    return 'unknown_unsafe' if value.match?(/no per[- ]tld status|each tld was not re-queried|not re-queried after rate limiting|summary-only|non-authoritative|not indicative of availability|does not indicate availability/)

    unsupported = value.match?(/tld is not supported|tld not supported|tld[- ]not[- ]supported|unsupported[- ]tld|explicit (?:registry )?denial|unsupported response|tld not supported by this registry interface|tld has no whois server/)
    reserved = value.match?(%r{reserved[- ](?:domain|policy|response|marker|list|notice|negative)|reserved/negative|reservation|prohibited|globalblock})
    has_registered = (value.match?(/\bregistered\b/) &&
      !value.match?(/(?:not|cannot(?: be)?|rather than|instead of falling through to|without|no)[- ]+registered\b|registered probe unresolved/) &&
      !value.match?(/legacy registered fixture/)) ||
                     value.match?(/domain-key presence for registration|active epp status|active, registrar locked|(?:centralnic|cira|verisign) (?:icann )?record|domain(?::| name)?\s+records?|domain name:.*epp status/)
    has_absence = value.match?(%r{authoritative absence|absence marker|absent response|no data found|no[- ]match|not[- ]found|no[- ]entries|no[- ]entry|no[- ]object|no[- ]record|no matching objects?|zero objects|does not exist|no such domain|not[- ]registered|available for registration|radix availability|radix available|purchase[- ]availability|availability sentence|\bfree responses?\b|registered/free|\bavailable response|\bavailable\b})
    explicitly_one_sided = value.match?(/absence only|absence verified, registered (?:probe )?unresolved|registered probe unresolved|absence probe (?:blocked|ambiguous|unresolved)|absence (?:ambiguous|blocked|unresolved)|legacy registered fixture remains covered|current probes both returned domain not found/)

    return 'unknown_unsafe' if reserved
    return 'explicit_unsupported' if unsupported

    if has_registered && has_absence && !explicitly_one_sided
      return 'paired'
    end
    # A package-level outcome named only "verified" does not identify which
    # evidence states were verified. Keep it unnormalized unless the row text
    # above independently names both sides.
    return 'registered_only' if has_registered
    return 'absence_only' if has_absence
    return 'unknown_unsafe' if value.match?(/unknown|unresolved|unavailable|unreachable|timeout|timed out|refus|reset|empty|rate limit|query limit|blocked|restricted|denied|denies|dns failure|does not resolve|no route|ambiguous|throttl|non-classif/)

    'report_detail_insufficient'
  end

  def self.empty_row(source, state, date, report, fixture, scope, note)
    {
      'source_rank' => source['source_rank'],
      'tld' => source['tld'],
      'source_status' => source['source_status'],
      'evidence_state' => state,
      'evidence_date' => date,
      'report_ref' => report,
      'fixture_ref' => fixture,
      'fixture_scope' => scope,
      'evidence_note' => note,
      'follow_up_state' => '',
      'follow_up_date' => '',
      'follow_up_report_ref' => '',
      'follow_up_fixture_ref' => '',
      'follow_up_note' => '',
    }
  end

  def self.add_report_rows!(ledger, source_by_rank, report, fixture, from_rank, to_rank)
    rows = markdown_table_rows(report).select { |row| (from_rank..to_rank).cover?(row['source_rank']) }
    if rows.length != (to_rank - from_rank + 1)
      raise "Expected #{to_rank - from_rank + 1} row entries in #{report}, found #{rows.length}"
    end

    date = report_date(report)
    fixture_ref, fixture_scope = fixture_fields(report, fixture)
    rows.each do |entry|
      source = source_by_rank.fetch(entry['source_rank'])
      raise "TLD mismatch at rank #{entry['source_rank']} in #{report}" unless source['tld'] == entry['tld']

      state = classify_detail(entry['detail'])
      # These three rows are pre-follow-up scorecard states. The current pair is
      # kept in follow-up fields below instead of rewriting the pinned baseline.
      if [104, 105].include?(entry['source_rank'])
        state = 'registered_only'
      end

      ledger[entry['source_rank']] = empty_row(
        source,
        state,
        date,
        report,
        fixture_ref,
        fixture_scope,
        entry['detail']
      )
    end
  end

  def self.add_top100!(ledger, source_by_rank)
    report = TOP100_PATH
    date = report_date(report)
    rows = markdown_table_rows(report)
    raise "Expected 100 Top 100 rows, found #{rows.length}" unless rows.length == 100

    rows.each do |entry|
      source = source_by_rank.fetch(entry['source_rank'])
      raise "TLD mismatch at rank #{entry['source_rank']} in #{report}" unless source['tld'] == entry['tld']

      label = entry['cells'][2].to_s.gsub('`', '').strip
      ledger[entry['source_rank']] = empty_row(
        source,
        summary_state(label),
        date,
        report,
        '',
        'not_reported',
        label
      )
    end
  end

  def self.parse_package1!(ledger, source_by_rank)
    report = PACKAGE1_REPORT
    fixture_ref, fixture_scope = fixture_fields(report, PACKAGE1_FIXTURES)
    date = report_date(report)

    markdown_table_rows(report).each do |entry|
      rank = entry['source_rank']
      next unless (301..1000).cover?(rank)

      source = source_by_rank.fetch(rank)
      raise "TLD mismatch at rank #{rank} in #{report}" unless source['tld'] == entry['tld']

      ledger[rank] = empty_row(
        source,
        classify_detail(entry['detail']),
        date,
        report,
        fixture_ref,
        fixture_scope,
        entry['detail']
      )
    end

    text = File.read(path(report))
    section = nil
    text.each_line do |line|
      section = 'unknown_unsafe' if line =~ /^## Unknown rows/
      section = 'unknown_unsafe' if line =~ /^## Unavailable rows/
      section = 'classification_only' if line =~ /^## Excluded classification-only rows/
      next unless section && line.start_with?('|')
      next if line =~ /^\|\s*Host\s*\|/ || line =~ /^\|\s*Classification\s*\|/ || line =~ /^\|[-:| ]+\|?$/

      line.scan(/(\d+):([a-z0-9-]+)/).each do |rank_text, label|
        rank = rank_text.to_i
        next unless (301..1000).cover?(rank)
        next if ledger.key?(rank)

        source = source_by_rank.fetch(rank)
        raise "TLD mismatch at rank #{rank} in #{report}" unless source['tld'] == label

        state = section
        note = section == 'classification_only' ? 'Source report lists this row as classification-only.' : 'Source report lists only an unavailable endpoint result.'
        ledger[rank] = empty_row(source, state, date, report, fixture_ref, fixture_scope, note)
      end
    end
  end

  def self.add_package_rows!(ledger, source_by_rank)
    planning = CSV.table(path(PLANNING_PATH)).to_h do |row|
      [row[:source_rank].to_i, row[:implementation_package].to_s]
    end

    PACKAGE_REPORTS.each do |package, (report, fixture)|
      date = report_date(report)
      fixture_ref, fixture_scope = fixture_fields(report, fixture)
      markdown_table_rows(report).each do |entry|
        rank = entry['source_rank']
        next unless (301..1000).cover?(rank)
        next unless planning[rank] == "package-#{package}"

        source = source_by_rank.fetch(rank)
        raise "TLD mismatch at rank #{rank} in #{report}" unless source['tld'] == entry['tld']

        # Package 2 includes Initial state before Outcome; packages 4-5 use
        # direct row evidence. Package 3's generic `verified` outcome is not
        # enough to promote a row to paired; only explicit row text can do that.
        context_index = package == 2 ? 4 : 3
        context = entry['cells'][context_index].to_s.downcase
        state = if package == 3 && context == 'excluded'
                  'classification_only'
                elsif package == 3 && context == 'unknown'
                  'unknown_unsafe'
                else
                  classify_detail(entry['detail'])
                end
        ledger[rank] = empty_row(source, state, date, report, fixture_ref, fixture_scope, entry['detail'])
      end
    end
  end

  def self.apply_follow_ups!(ledger)
    FOLLOW_UPS.each do |rank, follow_up|
      next unless ledger.key?(rank)

      row = ledger.fetch(rank)
      follow_up.each do |field, value|
        row[field] = value
      end
    end
  end

  def self.build
    source_rows = manifest_rows
    source_by_rank = source_rows.to_h { |row| [row['source_rank'], row] }
    expected_ranks = (1..1000).to_a
    ledger = {}

    add_top100!(ledger, source_by_rank)
    RANGE_REPORTS.each do |report, fixture|
      range = report.match(/(?:101-125|126-150|151-175|176-200|201-225|226-250|251-275|276-300)/)[0]
      first, last = range.split('-').map(&:to_i)
      add_report_rows!(ledger, source_by_rank, report, fixture, first, last)
    end
    parse_package1!(ledger, source_by_rank)
    add_package_rows!(ledger, source_by_rank)
    apply_follow_ups!(ledger)

    ranks = ledger.keys.sort
    raise "Ledger must cover ranks 1-1000 exactly once; got #{ranks.length} rows" unless ranks == expected_ranks
    raise "Unknown evidence states: #{(ledger.values.map { |row| row['evidence_state'] }.uniq - EVIDENCE_STATES).join(', ')}" unless (ledger.values.map { |row| row['evidence_state'] }.uniq - EVIDENCE_STATES).empty?

    ledger.values.sort_by { |row| row['source_rank'] }
  end

  def self.hand_audited_subset
    rows = build
    paired = rows.select { |row| row['source_rank'] > 100 && row['evidence_state'] == 'paired' }
    insufficient = rows.select { |row| row['evidence_state'] == 'report_detail_insufficient' }
    top100 = rows.select { |row| row['source_rank'] <= 100 }
    follow_ups = rows.select { |row| row['follow_up_state'] == 'paired' }

    raise "Expected 130 directly traceable rank-101+ pairs, found #{paired.length}" unless paired.length == 130
    raise "Expected 31 report-detail-insufficient rows, found #{insufficient.length}" unless insufficient.length == 31
    raise "Expected 100 Top-100 rows, found #{top100.length}" unless top100.length == 100
    raise "Expected 4 separately recorded paired follow-ups, found #{follow_ups.length}" unless follow_ups.length == 4

    subset = (top100 + paired + insufficient + follow_ups).uniq { |row| row['source_rank'] }.sort_by { |row| row['source_rank'] }
    expected_ranks = (top100 + paired + insufficient + follow_ups).map { |row| row['source_rank'] }.uniq.sort
    actual_ranks = subset.map { |row| row['source_rank'] }
    raise 'Hand-audited subset contains duplicate ranks' unless actual_ranks == expected_ranks

    subset
  end

  def self.write(output_path)
    rows = hand_audited_subset
    File.open(output_path, 'w') do |file|
      writer = CSV.new(file)
      writer << HEADERS
      rows.each { |row| writer << HEADERS.map { |header| row[header] } }
    end
    rows.length
  end
end

if $PROGRAM_NAME == __FILE__
  output = ARGV[0] || Top1000EvidenceLedger.path('docs/audits/data/whois-parser-top1000-evidence-ledger-subset-2026-09-25.csv')
  puts "wrote #{Top1000EvidenceLedger.write(output)} rows to #{output}"
end
