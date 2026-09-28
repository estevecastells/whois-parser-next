#!/usr/bin/env ruby
# Frozen audit gate for the DomScan 2026-09-28 high-demand WHOIS suffix snapshot.
# The usage CSV is intentionally pinned: the production log expires after 30 days.

require 'csv'
require 'digest'
require 'set'
require 'whois'
require 'whois-parser'

ROOT = File.expand_path('..', __dir__)
DATA = File.join(ROOT, 'docs/audits/data')
USAGE_PATH = File.join(DATA, 'domscan-whois-usage-2026-09-28.csv')
MANIFEST_PATH = File.join(DATA, 'domscan-whois-first-class-coverage-2026-09-28.csv')
IANA_PATH = File.join(DATA, 'domscan-whois-iana-services-2026-09-28.csv')
IANA_TLDS_PATH = File.join(DATA, 'domscan-whois-iana-tlds-alpha-2026-09-28.txt')
MAPPING_PATH = File.join(DATA, 'domscan-whois-parser-mapping-2026-09-28.csv')

EXPECTED_USAGE_SHA256 = '9eb67c2b9aa585076675fa529e52b27f43085576183ef64ea49fa3d5f3796bef'
EXPECTED_IANA_SHA256 = 'b8245877fa1e36a5209dbdd2968d57e8a0f3c4f18dc07730d681ccd42ef0b12e'
EXPECTED_IANA_TLDS_SHA256 = '074eed285e3167998d016bb23340bd2a91c92810f2e9016f066623372a11f0eb'
EXPECTED_MAPPING_SHA256 = '65388a40f13d438d909d3b3e57cf180803d095430898675c1239b8c976dbdd37'
EXPECTED_IANA_VERSION = '2026092800'
EXPECTED_ROWS = 153
EXPECTED_REQUESTS = 44_402
EXPECTED_MAPPING_ROWS = 113

PENDING_STATES = %w[structural_only protocol_conflict_pending unknown_only temporary_whois_safety_pending].freeze
ALLOWED_STATES = %w[
  fixture_pair unsupported_only rdap_only delegated_no_whois undelegated
  special_use retired web_adapter_only structural_only protocol_conflict_pending
  unknown_only registry_verified_temporary_whois restricted_registry_unknown_only
  restricted_registry_record_only
  temporary_whois_safety_pending multilabel_observation_only
].freeze

def digest(path)
  Digest::SHA256.file(path).hexdigest
end

def csv_rows(path)
  CSV.read(path, headers: true).map(&:to_h)
end

def parser_class_for(host)
  return '' if host.to_s.empty?

  Whois::Parser.parser_klass(host)&.name.to_s
rescue LoadError, Whois::ParserNotFound
  ''
end

def report_error(errors, message)
  errors << message
end

errors = []
strict = ARGV.delete('--strict')
strict_runtime = ARGV.delete('--strict-runtime')
unless ARGV.empty?
  warn "Usage: bundle exec ruby scripts/audit_domscan_whois_coverage.rb [--strict] [--strict-runtime]"
  exit 2
end

[
  [USAGE_PATH, EXPECTED_USAGE_SHA256],
  [IANA_PATH, EXPECTED_IANA_SHA256],
  [IANA_TLDS_PATH, EXPECTED_IANA_TLDS_SHA256],
  [MAPPING_PATH, EXPECTED_MAPPING_SHA256],
].each do |path, expected|
  report_error(errors, "missing pinned source: #{path.delete_prefix(ROOT + '/')}") unless File.file?(path)
  next unless File.file?(path)

  actual = digest(path)
  report_error(errors, "SHA-256 changed for #{path.delete_prefix(ROOT + '/')}: #{actual}") unless actual == expected
end

if errors.empty?
  usage = csv_rows(USAGE_PATH)
  cohort = usage.select { |row| row.fetch('requests').to_i > 5 }
  manifest = csv_rows(MANIFEST_PATH)
  iana = csv_rows(IANA_PATH).to_h { |row| [row.fetch('tld'), row] }
  usage_mapping = csv_rows(MAPPING_PATH).to_h { |row| [row.fetch('tld'), row] }
  root_labels = File.readlines(IANA_TLDS_PATH, chomp: true)
                     .reject { |line| line.empty? || line.start_with?('#') }
                     .map(&:downcase)
                     .to_set

  report_error(errors, "usage threshold produced #{cohort.size} rows, expected #{EXPECTED_ROWS}") unless cohort.size == EXPECTED_ROWS
  report_error(errors, "usage threshold produced #{cohort.sum { |row| row.fetch('requests').to_i }} requests, expected #{EXPECTED_REQUESTS}") unless cohort.sum { |row| row.fetch('requests').to_i } == EXPECTED_REQUESTS
  report_error(errors, "manifest has #{manifest.size} rows, expected #{EXPECTED_ROWS}") unless manifest.size == EXPECTED_ROWS

  usage_by_tld = cohort.to_h { |row| [row.fetch('tld'), row] }
  manifest_by_tld = manifest.to_h { |row| [row.fetch('tld'), row] }
  report_error(errors, 'manifest has duplicate suffix rows') unless manifest_by_tld.size == manifest.size
  report_error(errors, 'manifest suffix set differs from the pinned usage threshold') unless manifest_by_tld.keys.sort == usage_by_tld.keys.sort
  report_error(errors, "IANA snapshot has #{iana.size} pages, expected 141") unless iana.size == 141
  report_error(errors, "traditional WHOIS host map has #{usage_mapping.size} rows, expected #{EXPECTED_MAPPING_ROWS}") unless usage_mapping.size == EXPECTED_MAPPING_ROWS

  pending = []
  route_reviews = []
  route_blockers = []

  manifest.each do |row|
    tld = row.fetch('tld')
    source = usage_by_tld[tld]
    next unless source

    %w[requests http_200 traditional_whois_used].each do |field|
      unless row.fetch(field).to_i == source.fetch(field).to_i
        report_error(errors, ".#{tld}: manifest #{field}=#{row[field]} differs from usage snapshot #{source[field]}")
      end
    end

    evidence_state = row.fetch('evidence_state').to_s
    unless ALLOWED_STATES.include?(evidence_state)
      report_error(errors, ".#{tld}: unrecognized evidence_state=#{evidence_state.inspect}")
    end
    %w[registry_protocol_state registry_evidence_url first_class_treatment route_evidence_state route_blocker_state].each do |field|
      report_error(errors, ".#{tld}: #{field} must be explicit") if row[field].to_s.strip.empty?
    end
    if row['suffix_scope'] != 'final_label_aggregate' || row['multilabel_scope_note'].to_s.empty?
      report_error(errors, ".#{tld}: final-label aggregation or multi-label limitation is undocumented")
    end

    root_state = row.fetch('root_zone_state')
    if root_state == 'delegated_in_iana_tlds_alpha'
      unless root_labels.include?(tld.downcase)
        report_error(errors, ".#{tld}: marked delegated but absent from pinned IANA TLD alpha file")
      end
      page = iana[tld]
      if page.nil?
        report_error(errors, ".#{tld}: delegated suffix has no row in the IANA service snapshot")
      else
        report_error(errors, ".#{tld}: IANA page returned HTTP #{page['http_status']}") unless page['http_status'] == '200'
        report_error(errors, ".#{tld}: IANA version mismatch") unless page['iana_version'] == EXPECTED_IANA_VERSION
        %w[iana_page protocol_state whois_server rdap_server page_last_updated retrieved_at].each do |source_field|
          manifest_field = {
            'iana_page' => 'registry_evidence_url',
            'iana_protocol_state' => 'iana_protocol_state',
            'protocol_state' => 'iana_protocol_state',
            'whois_server' => 'iana_whois_server',
            'rdap_server' => 'iana_rdap_server',
            'retrieved_at' => 'iana_retrieved_at',
            'page_last_updated' => 'iana_page_last_updated',
          }.fetch(source_field, source_field)
          unless row[manifest_field].to_s == page[source_field].to_s
            report_error(errors, ".#{tld}: #{manifest_field} differs from pinned IANA page snapshot")
          end
        end
      end
    elsif root_state == 'not_in_iana_tlds_alpha'
      report_error(errors, ".#{tld}: marked undelegated but present in pinned IANA TLD alpha file") if root_labels.include?(tld.downcase)
      report_error(errors, ".#{tld}: undelegated row must link to the pinned alpha file") unless row['registry_evidence_url'] == 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt'
    elsif root_state == 'special_use'
      report_error(errors, ".#{tld}: unexpected special-use suffix") unless tld == 'local'
      report_error(errors, ".#{tld}: special-use row lacks IANA evidence URL") unless row['registry_evidence_url'].to_s.include?('iana.org/assignments/special-use-domain-names')
    else
      report_error(errors, ".#{tld}: invalid root_zone_state=#{root_state.inspect}")
    end

    route_sample = tld == 'za' ? 'example.co.za' : "example.#{tld}"
    route = Whois::Server.find_for_domain(route_sample)
    runtime_host = route&.host.to_s
    runtime_adapter = route&.class&.name.to_s
    runtime_route_parser = parser_class_for(runtime_host)
    unless row['client_route_host'].to_s == runtime_host && row['client_route_adapter_class'].to_s == runtime_adapter && row['library_route_parser_class'].to_s == runtime_route_parser
      report_error(errors, ".#{tld}: installed whois gem route differs from the pinned manifest")
    end

    expected_iana_parser = parser_class_for(row['iana_whois_server'])
    expected_observed_parser = parser_class_for(row['observed_whois_host'])
    unless row['iana_host_parser_class'].to_s == expected_iana_parser
      report_error(errors, ".#{tld}: IANA-host parser class differs from current parser tree")
    end
    unless row['observed_host_parser_class'].to_s == expected_observed_parser
      report_error(errors, ".#{tld}: observed-host parser class differs from current parser tree")
    end
    preferred_parser = if %w[registry_verified_temporary_whois temporary_whois_safety_pending].include?(evidence_state)
                         parser_class_for(row['client_route_host'])
                       elsif !expected_iana_parser.empty?
                         expected_iana_parser
                       else
                         expected_observed_parser
                       end
    unless row['parser_class'].to_s == preferred_parser
      report_error(errors, ".#{tld}: preferred direct-host parser class differs from current parser tree")
    end

    if row['route_blocker_state'].to_s.start_with?('covered_by_existing_domscan_route_mapping')
      mapping = usage_mapping[tld]
      report_error(errors, ".#{tld}: existing DomScan route state has no pinned host-map row") unless mapping
      if mapping
        report_error(errors, ".#{tld}: existing DomScan host map differs from observed WHOIS host") unless mapping['whois_host'] == row['observed_whois_host']
        report_error(errors, ".#{tld}: existing DomScan host map differs from the observed parser class") unless mapping['parser_class'] == row['observed_host_parser_class']
      end
    end

    spec_fields = %w[registered_spec absence_spec unknown_spec]
    spec_fields.each do |field|
      row[field].to_s.split(';').map(&:strip).reject(&:empty?).each do |relative_path|
        unless relative_path.start_with?('spec/') && File.file?(File.join(ROOT, relative_path))
          report_error(errors, ".#{tld}: #{field} references missing/non-spec file #{relative_path.inspect}")
        end
      end
    end

    if evidence_state == 'fixture_pair'
      report_error(errors, ".#{tld}: fixture_pair requires a direct parser class") if row['parser_class'].to_s.empty?
      %w[registered_spec absence_spec].each do |field|
        report_error(errors, ".#{tld}: fixture_pair has no #{field}") if row[field].to_s.empty?
      end
      if source.fetch('traditional_whois_used').to_i.positive? && row['observed_whois_host'].to_s.empty?
        report_error(errors, ".#{tld}: observed traditional WHOIS use has no recorded host")
      end
    elsif evidence_state == 'unsupported_only'
      report_error(errors, ".#{tld}: unsupported_only requires IANA RDAP-only evidence") unless row['iana_protocol_state'] == 'rdap_only'
      report_error(errors, ".#{tld}: unsupported_only requires a direct parser class and unknown-response spec") if row['parser_class'].to_s.empty? || row['unknown_spec'].to_s.empty?
    elsif evidence_state == 'rdap_only'
      report_error(errors, ".#{tld}: RDAP-only classification conflicts with IANA protocol evidence") unless row['iana_protocol_state'] == 'rdap_only'
      report_error(errors, ".#{tld}: RDAP-only classification has traditional WHOIS traffic") if source.fetch('traditional_whois_used').to_i.positive?
      report_error(errors, ".#{tld}: RDAP-only row lacks explicit treatment") if row['first_class_treatment'].to_s.empty?
    elsif evidence_state == 'delegated_no_whois'
      report_error(errors, ".#{tld}: no-WHOIS classification conflicts with IANA service fields") unless row['iana_protocol_state'] == 'no_server_listed'
      report_error(errors, ".#{tld}: no-WHOIS classification has traditional calls") if source.fetch('traditional_whois_used').to_i.positive?
    elsif evidence_state == 'web_adapter_only'
      report_error(errors, ".#{tld}: Web adapter classification lacks runtime Web adapter") unless runtime_adapter == 'Whois::Server::Adapters::Web'
      report_error(errors, ".#{tld}: Web adapter classification conflicts with IANA WHOIS/RDAP") unless row['iana_protocol_state'] == 'no_server_listed'
      report_error(errors, ".#{tld}: Web adapter classification has traditional calls") if source.fetch('traditional_whois_used').to_i.positive?
    elsif evidence_state == 'undelegated'
      report_error(errors, ".#{tld}: undelegated row has traditional WHOIS calls") if source.fetch('traditional_whois_used').to_i.positive?
    elsif evidence_state == 'special_use'
      report_error(errors, ".#{tld}: private special-use row has traditional calls") if source.fetch('traditional_whois_used').to_i.positive?
    elsif evidence_state == 'retired'
      report_error(errors, ".#{tld}: retired service requires an unknown-response regression spec") if row['unknown_spec'].to_s.empty?
    elsif %w[registry_verified_temporary_whois temporary_whois_safety_pending].include?(evidence_state)
      report_error(errors, ".#{tld}: temporary WHOIS exception must preserve IANA's raw RDAP-only state") unless row['iana_protocol_state'] == 'rdap_only'
      report_error(errors, ".#{tld}: temporary WHOIS exception is only accepted for .uk") unless tld == 'uk'
      report_error(errors, ".#{tld}: temporary WHOIS exception lacks official registry evidence") unless row['protocol_exception_evidence_url'] == 'https://theukdomain.uk/rdap/'
      report_error(errors, ".#{tld}: temporary WHOIS exception has no expiry date") unless row['registry_protocol_state'] == 'whois_active_until_2027-02-09_nominet'
      report_error(errors, ".#{tld}: temporary WHOIS exception requires registered, absence, and unknown specs") if %w[registered_spec absence_spec unknown_spec].any? { |field| row[field].to_s.empty? }
      report_error(errors, ".#{tld}: temporary WHOIS exception must be routed to whois.nic.uk") unless row['client_route_host'] == 'whois.nic.uk'
      report_error(errors, ".#{tld}: temporary WHOIS exception is missing its parser class") if row['parser_class'].to_s.empty?
    elsif evidence_state == 'restricted_registry_unknown_only'
      report_error(errors, ".#{tld}: restricted unknown-only state is only accepted for .open") unless tld == 'open'
      report_error(errors, ".#{tld}: restricted unknown-only state requires IANA WHOIS and RDAP") unless row['iana_protocol_state'] == 'whois_and_rdap' && row['iana_whois_server'] == 'whois.nic.open'
      report_error(errors, ".#{tld}: restricted unknown-only state must have zero observed traditional WHOIS calls") if source.fetch('traditional_whois_used').to_i.positive?
      report_error(errors, ".#{tld}: restricted unknown-only state requires the official Amex registration policy") unless row['registry_policy_evidence_url'] == 'https://web.aexp-static.com/content/dam/amex/us/staticassets/pdf/nic/Registry-Policies-OPEN.pdf' && !row['registry_policy_note'].to_s.empty?
      report_error(errors, ".#{tld}: restricted unknown-only state requires a direct no-data safety spec") if row['unknown_spec'].to_s.empty?
      report_error(errors, ".#{tld}: restricted unknown-only state must not claim a positive parser class") unless row['parser_class'].to_s.empty?
      report_error(errors, ".#{tld}: restricted unknown-only state must preserve the missing client route") unless row['client_route_host'].to_s.empty? && runtime_adapter == 'Whois::Server::Adapters::None'
      report_error(errors, ".#{tld}: restricted unknown-only state must leave registered/absence specs empty") unless row['registered_spec'].to_s.empty? && row['absence_spec'].to_s.empty?
    elsif evidence_state == 'restricted_registry_record_only'
      report_error(errors, ".#{tld}: restricted record-only state is only accepted for .open") unless tld == 'open'
      report_error(errors, ".#{tld}: restricted record-only state requires IANA WHOIS and RDAP") unless row['iana_protocol_state'] == 'whois_and_rdap' && row['iana_whois_server'] == 'whois.nic.open'
      report_error(errors, ".#{tld}: restricted record-only state must have zero observed traditional WHOIS calls") if source.fetch('traditional_whois_used').to_i.positive?
      report_error(errors, ".#{tld}: restricted record-only state requires the official Amex registration policy") unless row['registry_policy_evidence_url'] == 'https://web.aexp-static.com/content/dam/amex/us/staticassets/pdf/nic/Registry-Policies-OPEN.pdf' && !row['registry_policy_note'].to_s.empty?
      report_error(errors, ".#{tld}: restricted record-only state requires a registered-record spec") if row['registered_spec'].to_s.empty?
      report_error(errors, ".#{tld}: restricted record-only state requires a No Data Found unknown spec") if row['unknown_spec'].to_s.empty?
      report_error(errors, ".#{tld}: restricted record-only state must not claim authoritative absence") unless row['absence_spec'].to_s.empty?
      report_error(errors, ".#{tld}: restricted record-only state requires the exact .open parser class") unless row['parser_class'] == 'Whois::Parsers::WhoisNicOpen'
      report_error(errors, ".#{tld}: restricted record-only state must preserve the missing installed-library route") unless row['client_route_host'].to_s.empty? && runtime_adapter == 'Whois::Server::Adapters::None'
      %w[Bounded WHOIS observation minimal synthetic no copied or redacted raw WHOIS bodies].each do |phrase|
        report_error(errors, ".#{tld}: evidence note must distinguish live observation from synthetic tests") unless row['evidence_note'].to_s.include?(phrase)
      end
      open_fixture_dir = File.join(ROOT, 'spec/fixtures/responses/whois.nic.open/open')
      %w[registered_synthetic.txt no_data_synthetic.txt].each do |filename|
        report_error(errors, ".#{tld}: synthetic parser fixture is missing #{filename}") unless File.file?(File.join(open_fixture_dir, filename))
      end
      %w[registered_nic_open_current_redacted.txt no_data_current.txt].each do |filename|
        report_error(errors, ".#{tld}: raw registry fixture must not be retained as #{filename}") if File.exist?(File.join(open_fixture_dir, filename))
      end
    elsif evidence_state == 'multilabel_observation_only'
      report_error(errors, ".#{tld}: multi-label observation-only state is only accepted for .za") unless tld == 'za'
      report_error(errors, ".#{tld}: IANA .za must remain no-server-listed") unless row['iana_protocol_state'] == 'no_server_listed'
      report_error(errors, ".#{tld}: multi-label service observation must be the co.za route") unless row['observed_whois_host'] == 'coza-whois.registry.net.za' && row['parser_class'] == 'Whois::Parsers::CozaWhoisRegistryNetZa'
      report_error(errors, ".#{tld}: multi-label route observation requires registered and absence specs") if row['registered_spec'].to_s.empty? || row['absence_spec'].to_s.empty?
      report_error(errors, ".#{tld}: multi-label observation lacks the aggregate-scope caveat") unless row['multilabel_scope_note'].to_s.include?('.co.za volume cannot be isolated')
    end

    pending << row if PENDING_STATES.include?(evidence_state)
    route_blockers << row unless row['route_blocker_state'].to_s.empty? || row['route_blocker_state'] == 'none' || row['route_blocker_state'].to_s.start_with?('covered_by_existing_domscan_route_mapping')
    if row['route_evidence_state'].to_s.match?(/differs|stale|missing_from_library|not_listed|overrides/)
      route_reviews << row
    end
  end

  puts "Snapshot: #{manifest.size} suffixes, #{manifest.sum { |row| row['requests'].to_i }} API items; usage SHA-256 #{digest(USAGE_PATH)}"
  puts "IANA: #{iana.size} pages, version #{EXPECTED_IANA_VERSION}; service snapshot SHA-256 #{digest(IANA_PATH)}"
  puts "Coverage: #{manifest.count { |row| row['evidence_state'] == 'fixture_pair' }} registered/absence parser regression pairs (not a count of live captures), #{manifest.count { |row| row['evidence_state'] == 'multilabel_observation_only' }} multi-label route observations, #{manifest.count { |row| row['evidence_state'] == 'registry_verified_temporary_whois' }} resolved temporary WHOIS exceptions, #{manifest.count { |row| row['evidence_state'] == 'temporary_whois_safety_pending' }} temporary WHOIS safety pending, #{manifest.count { |row| row['evidence_state'] == 'restricted_registry_unknown_only' }} restricted unknown-only, #{manifest.count { |row| row['evidence_state'] == 'restricted_registry_record_only' }} restricted record-only, #{manifest.count { |row| row['evidence_state'] == 'rdap_only' }} RDAP-only, #{manifest.count { |row| row['evidence_state'] == 'unsupported_only' }} explicitly unsupported, #{manifest.count { |row| row['evidence_state'] == 'retired' }} retired, #{pending.size} pending"
  puts "Traditional WHOIS usage map: #{usage_mapping.size} rows; SHA-256 #{digest(MAPPING_PATH)}"

  unless pending.empty?
    puts 'Pending first-class rows:'
    pending.sort_by { |row| -row['requests'].to_i }.each do |row|
      puts format('  .%-14s %6d requests, %4d traditional WHOIS; %s', row['tld'], row['requests'].to_i, row['traditional_whois_used'].to_i, row['first_class_treatment'])
    end
  end

  unless route_reviews.empty?
    puts "Route evidence review: #{route_reviews.size} rows differ from IANA, DomScan-observed, or installed whois 6.0.3 host evidence; see route_evidence_state in the manifest."
  end

  unless route_blockers.empty?
    grouped_blockers = route_blockers.group_by { |row| row['route_blocker_state'] }
    puts "Runtime route blockers: #{route_blockers.size} suffixes (#{route_blockers.sum { |row| row['requests'].to_i }} API items)"
    grouped_blockers.sort.each do |state, rows|
      puts "  #{state}: #{rows.size} suffixes"
    end
    rdap_route_rows = route_blockers.select do |row|
      %w[rdap_only_suffix_still_has_installed_whois_route rdap_only_legacy_route_requires_application_skip].include?(row['route_blocker_state'])
    end
    rdap_legacy_rows = rdap_route_rows.select { |row| row['route_evidence_state'].to_s.match?(/legacy|historical/) }
    rdap_stale_rows = rdap_route_rows - rdap_legacy_rows
    puts "  RDAP-only route detail: #{rdap_stale_rows.size} stale configured routes; #{rdap_legacy_rows.size} historical observed routes requiring application skips (#{rdap_legacy_rows.map { |row| ".#{row['tld']}" }.join(', ')})"
    puts 'Blocked suffixes:'
    route_blockers.sort_by { |row| -row['requests'].to_i }.each do |row|
      puts format('  .%-14s %6d requests; %s', row['tld'], row['requests'].to_i, row['route_blocker_state'])
    end
    puts 'The runtime list includes route corrections, RDAP-only routes that need application skips, and explicit retirement/multi-label exceptions.'
  end

  existing_domscan_routes = manifest.select do |row|
    row['route_blocker_state'].to_s.start_with?('covered_by_existing_domscan_route_mapping')
  end
  unless existing_domscan_routes.empty?
    puts "Verified existing DomScan route mappings: #{existing_domscan_routes.size} suffixes (#{existing_domscan_routes.sum { |row| row['requests'].to_i }} API items); listed separately from unresolved blockers."
    existing_domscan_routes.sort_by { |row| -row['requests'].to_i }.each do |row|
      puts format('  .%-14s %6d requests; %s', row['tld'], row['requests'].to_i, row['route_blocker_state'])
    end
  end

  unless errors.empty?
    warn 'Coverage audit integrity failures:'
    errors.each { |message| warn "  - #{message}" }
  end

  if strict && pending.any?
    warn "Strict coverage gate failed: #{pending.size} row(s) still need parser truth evidence or service-resolution evidence."
  end
  if strict_runtime && (!pending.empty? || !route_blockers.empty?)
    warn "Strict runtime gate failed: #{pending.size} parser-pending row(s), #{route_blockers.size} route blocker(s)."
  end
  exit(errors.empty? && (!strict || pending.empty?) && (!strict_runtime || (pending.empty? && route_blockers.empty?)) ? 0 : 1)
end

unless errors.empty?
  warn 'Coverage audit integrity failures:'
  errors.each { |message| warn "  - #{message}" }
  exit 1
end
