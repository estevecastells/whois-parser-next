require 'spec_helper'
require 'open3'
require 'rbconfig'

RSpec.describe 'DomScan WHOIS coverage manifest' do
  ROOT = File.expand_path('../..', __dir__)
  SCRIPT = File.join(ROOT, 'scripts/audit_domscan_whois_coverage.rb')

  def run_audit(*args)
    Open3.capture3(RbConfig.ruby, SCRIPT, *args, chdir: ROOT)
  end

  it 'validates the pinned 153-suffix and IANA source snapshots' do
    stdout, stderr, status = run_audit

    expect(status.exitstatus).to eq(0), stderr
    expect(stdout).to include('Snapshot: 153 suffixes, 44402 API items')
    expect(stdout).to include('IANA: 141 pages, version 2026092800')
    expect(stdout).to include('registered/absence parser regression pairs (not a count of live captures)')
    expect(stdout).to include('1 restricted record-only')
    expect(stdout).to match(/Runtime route blockers: \d+ suffixes/)
    expect(stdout).to include('rdap_only_suffix_still_has_installed_whois_route')
    expect(stdout).to include('RDAP-only route detail: 36 stale configured routes; 2 historical observed routes')
    expect(stdout).to include('installed_library_route_differs_from_current_iana_host')
    expect(stderr).not_to include('integrity failures')
  end

  it 'fails strict coverage while any row still needs first-class evidence' do
    stdout, stderr, status = run_audit('--strict')
    pending_count = stdout[/, (\d+) pending/, 1]&.to_i

    expect(pending_count).not_to be_nil, [stdout, stderr].join("\n")
    if pending_count.zero?
      expect(status.exitstatus).to eq(0), stderr
    else
      expect(status.exitstatus).to eq(1)
      expect(stderr).to include('Strict coverage gate failed')
      expect(stdout).to include('Pending first-class rows:')
    end
  end

  it 'keeps parser evidence and installed runtime route blockers as separate strict gates' do
    stdout, stderr, status = run_audit('--strict-runtime')
    pending_count = stdout[/, (\d+) pending/, 1]&.to_i
    blocker_count = stdout[/Runtime route blockers: (\d+) suffixes/, 1]&.to_i

    expect(pending_count).not_to be_nil, [stdout, stderr].join("\n")
    expect(blocker_count).not_to be_nil, [stdout, stderr].join("\n")
    if pending_count.zero? && blocker_count.zero?
      expect(status.exitstatus).to eq(0), stderr
    else
      expect(status.exitstatus).to eq(1)
      expect(stderr).to include('Strict runtime gate failed')
    end
  end
end
