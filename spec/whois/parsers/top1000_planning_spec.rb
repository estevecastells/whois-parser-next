require 'csv'
require 'spec_helper'

RSpec.describe Whois::Parser, 'ICANN DNS Magnitude ranks 301-1000 planning' do
  let(:planning_path) do
    File.expand_path('../../../docs/audits/data/whois-parser-top1000-planning.csv', __dir__)
  end

  let(:rows) { CSV.read(planning_path, headers: true).map(&:to_h) }

  it 'assigns every source rank 301-1000 exactly once across five balanced packages' do
    expect(rows.map { |row| Integer(row.fetch('source_rank')) }).to eq((301..1000).to_a)
    expect(rows.map { |row| row.fetch('tld') }.uniq.length).to eq(700)
    expect(rows.map { |row| row.fetch('implementation_package') }.uniq)
      .to contain_exactly('package-1', 'package-2', 'package-3', 'package-4', 'package-5')

    package_counts = rows.group_by { |row| row.fetch('implementation_package') }
                        .transform_values(&:length)
    expect(package_counts).to eq(
      'package-1' => 140,
      'package-2' => 140,
      'package-3' => 140,
      'package-4' => 140,
      'package-5' => 140
    )
  end

  it 'keeps each non-empty WHOIS host owned by one package' do
    rows.group_by { |row| row.fetch('whois_host') }
        .reject { |host, _| host.empty? }
        .each do |host, host_rows|
      packages = host_rows.map { |row| row.fetch('implementation_package') }.uniq
      expect(packages).to have_attributes(length: 1), "#{host} is split across #{packages.inspect}"
    end
  end

  it 'keeps shared parser families in one package and isolates non-parser rows' do
    rows.group_by { |row| row.fetch('parser_family') }
        .reject { |family, _| family == 'Blank' }
        .each do |family, family_rows|
      packages = family_rows.map { |row| row.fetch('implementation_package') }.uniq
      expect(packages).to have_attributes(length: 1), "#{family} is split across #{packages.inspect}"
    end

    rows.select { |row| row.fetch('source_status') != 'delegated' }.each do |row|
      expected_state = row.fetch('source_status') == 'special-use' ? 'excluded_special_use' : 'excluded_undelegated'
      expect(row.fetch('initial_coverage_state')).to eq(expected_state), row.inspect
    end

    rows.select { |row| row.fetch('server_adapter') == 'Web' }.each do |row|
      expect(row.fetch('initial_coverage_state')).to eq('web_adapter_excluded'), row.inspect
      expect(row.fetch('whois_host')).to be_empty
    end
  end
end
