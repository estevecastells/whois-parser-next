require 'csv'
require 'spec_helper'
require 'whois/parsers/blank'

RSpec.describe Whois::Parser, 'ICANN DNS Magnitude package-5 coverage' do
  FIXTURE_ROOT = 'responses/top1000_package5'

  let(:planning_path) do
    File.expand_path('../../../docs/audits/data/whois-parser-top1000-planning.csv', __dir__)
  end

  let(:rows) do
    CSV.read(planning_path, headers: true).select do |row|
      row['implementation_package'] == 'package-5'
    end
  end

  def parser_for(host, fixture_name)
    body = File.read(fixture(FIXTURE_ROOT, fixture_name))
    described_class.parser_for(Whois::Record::Part.new(body: body, host: host))
  end

  it 'keeps all 140 assigned rows represented in the package audit inventory' do
    expect(rows.length).to eq(140)
    expect(rows.map { |row| row['source_rank'].to_i }).to eq(
      rows.map { |row| row['source_rank'].to_i }.sort
    )
    expect(rows.map { |row| row['tld'] }.uniq.length).to eq(140)
    expect(rows.count { |row| row['source_status'] == 'delegated' }).to eq(110)
    expect(rows.count { |row| row['source_status'] != 'delegated' }).to eq(30)
  end

  describe 'Identity Digital key/value adapters' do
    no_data_hosts = %w[
      whois.nic.bid whois.nic.men whois.nic.moe whois.nic.racing
      whois.nic.review whois.nic.trade whois.nic.wiki
    ]
    domain_not_found_hosts = %w[
      whois.nic.beauty whois.nic.bmw whois.nic.build whois.nic.dvag
      whois.nic.frl whois.nic.inc whois.nic.lat whois.nic.luxury whois.nic.saarland
      whois.nic.sbs whois.nic.storage whois.nic.tickets
    ]
    short_domain_not_found_hosts = %w[whois.nic.barclays whois.nic.moscow]
    no_matching_hosts = %w[
      whois.nic.gal whois.nic.scot whois.nic.swiss
    ]

    (no_data_hosts + domain_not_found_hosts + no_matching_hosts).each do |host|
      it "parses a current registered record for #{host}" do
        parser = parser_for(host, 'identity_registered.txt')

        expect(parser.registered?).to eq(true)
        expect(parser.available?).to eq(false)
        expect(parser.domain).to eq('google.example')
        expect(parser.nameservers.map(&:name)).to eq(%w[ns1.example.net ns2.example.net])
      end
    end

    no_data_hosts.each do |host|
      it "recognises the authoritative No Data Found marker for #{host}" do
        parser = parser_for(host, 'identity_no_data.txt')

        expect(parser.available?).to eq(true)
        expect(parser.registered?).to eq(false)
      end
    end

    domain_not_found_hosts.each do |host|
      it "recognises the authoritative DOMAIN NOT FOUND marker for #{host}" do
        parser = parser_for(host, 'identity_domain_not_found.txt')

        expect(parser.available?).to eq(true)
        expect(parser.registered?).to eq(false)
      end
    end

    short_domain_not_found_hosts.each do |host|
      it "recognises the authoritative short Domain not found marker for #{host}" do
        parser = parser_for(host, 'identity_domain_not_found_short.txt')

        expect(parser.available?).to eq(true)
        expect(parser.registered?).to eq(false)
      end
    end

    no_matching_hosts.each do |host|
      it "recognises the authoritative no matching objects marker for #{host}" do
        parser = parser_for(host, 'identity_no_matching.txt')

        expect(parser.available?).to eq(true)
        expect(parser.registered?).to eq(false)
      end
    end
  end

  it 'handles the registry-specific absence markers without broad inference' do
    expect(parser_for('whois.nic.amsterdam', 'identity_free.txt').available?).to eq(true)
    expect(parser_for('whois.nic.observer', 'identity_available_phrase.txt').available?).to eq(true)
    expect(parser_for('whois.nic.press', 'identity_available_phrase.txt').available?).to eq(true)
    expect(parser_for('whois.nic.xn--80adxhks', 'identity_domain_not_found_short.txt').available?).to eq(true)
    expect(parser_for('whois.nic.xn--t60b56a', 'identity_no_match.txt').available?).to eq(true)
    expect(parser_for('whois.gtld.knet.cn', 'identity_knet_missing.txt').available?).to eq(true)
    expect(parser_for('whois.ryce-rsp.com', 'identity_ryce_available.txt').available?).to eq(true)

    knet_unknown = described_class.parser_for(
      Whois::Record::Part.new(
        body: File.read(fixture('responses', 'top1000_safety/unknown_object_marker.txt')),
        host: 'whois.gtld.knet.cn'
      )
    )
    expect(knet_unknown.status).to eq(:unknown)
    expect(knet_unknown.available?).to eq(false)
    expect(knet_unknown.registered?).to eq(false)
  end

  it 'parses the AFNIC .yt response and its explicit absence marker' do
    registered = parser_for('whois.nic.yt', 'afnic_registered.txt')
    available = parser_for('whois.nic.yt', 'afnic_available.txt')

    expect(registered.registered?).to eq(true)
    expect(registered.available?).to eq(false)
    expect(registered.nameservers.map(&:name)).to eq(%w[ns1.markmonitor.com ns3.markmonitor.com])
    expect(available.available?).to eq(true)
    expect(available.registered?).to eq(false)
  end

  it 'parses the JWhoisServer .gf response and its explicit absence marker' do
    registered = parser_for('whois.mediaserv.net', 'jwhois_registered.txt')
    available = parser_for('whois.mediaserv.net', 'jwhois_available.txt')

    expect(registered.registered?).to eq(true)
    expect(registered.available?).to eq(false)
    expect(registered.nameservers.map(&:name)).to eq(%w[ns1.google.com ns2.google.com])
    expect(available.available?).to eq(true)
    expect(available.registered?).to eq(false)

    domain_only = described_class.parser_for(
      Whois::Record::Part.new(
        body: File.read(fixture('responses', 'top1000_safety/jwhois_domain_only.txt')),
        host: 'whois.mediaserv.net'
      )
    )
    expect(domain_only.status).to eq(:unknown)
    expect(domain_only.available?).to eq(false)
    expect(domain_only.registered?).to eq(false)
  end

  it 'keeps empty and ambiguous responses unknown' do
    [
      parser_for('whois.nic.bid', 'empty.txt'),
      parser_for('whois.nic.bid', 'ambiguous_domain_only.txt'),
      parser_for('whois.mediaserv.net', 'empty.txt'),
    ].each do |parser|
      if parser.response_unavailable?
        expect { parser.status }.to raise_error(Whois::ResponseIsUnavailable)
        expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable)
        expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable)
      else
        expect(parser.status).to eq(:unknown)
        expect(parser.available?).to eq(false)
        expect(parser.registered?).to eq(false)
      end
    end
  end

  it 'keeps an explicit unsupported-registry denial unavailable' do
    require 'whois/parsers/base_unsupported_registry'
    parser = Whois::Parsers::BaseUnsupportedRegistry.new(
      Whois::Record::Part.new(body: File.read(fixture(FIXTURE_ROOT, 'unsupported.txt')))
    )

    expect(parser.response_unavailable?).to eq(true)
    expect { parser.status }.to raise_error(Whois::ResponseIsUnavailable)
    expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable)
    expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable)
  end

  it 'selects non-Blank adapters for every package-owned host with positive evidence' do
    hosts = %w[
      cwhois.cnnic.cn whois.aero whois.afilias-grs.info whois.dotpostregistry.net
      whois.gtld.knet.cn whois.madrid.rs.corenic.net whois.mediaserv.net
      whois.nic.amsterdam whois.nic.barclays whois.nic.beauty whois.nic.bid whois.nic.bmw
      whois.nic.build whois.nic.dvag whois.nic.frl whois.nic.gal whois.nic.inc whois.nic.lat
      whois.nic.luxury whois.nic.men whois.nic.moe whois.nic.moscow whois.nic.observer
      whois.nic.press whois.nic.racing whois.nic.review whois.nic.saarland
      whois.nic.sbs whois.nic.scot whois.nic.storage whois.nic.swiss
      whois.nic.tickets whois.nic.trade whois.nic.wiki
      whois.nic.xn--80adxhks whois.nic.xn--t60b56a whois.nic.yt
      whois.nic.cx whois.nic.gs whois.nic.tc whois.nic.travel whois.tld.sy
      whois.online.rs.corenic.net whois.ryce-rsp.com
    ]

    hosts.each do |host|
      expect(described_class.parser_klass(host)).not_to eq(Whois::Parsers::Blank), host
    end
  end
end
