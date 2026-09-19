require 'spec_helper'

require 'whois/parsers/blank'

require 'whois/parsers/whois.nic.works'
require 'whois/parsers/whois.nic.systems'
require 'whois/parsers/whois.nic.business'
require 'whois/parsers/whois.nic.news'
require 'whois/parsers/whois.nic.one'
require 'whois/parsers/whois.kenic.or.ke'
require 'whois/parsers/whois.dns.hr'
require 'whois/parsers/whois.nic.md'
require 'whois/parsers/whois.nic.ly'
require 'whois/parsers/whois.amnic.net'

AUDIT_101_125_FIXTURE_ROOT = 'responses/audit_20260919_ranks101_125'.freeze
AUDIT_101_125_TLDS = %w[
  apple zone top uz sa lan works gt systems lv bz so one ke hr md st ly
  business np am ge ba news et
].freeze

RSpec.describe Whois::Parser, 'ICANN DNS Magnitude source ranks 101-125 audit' do
  def parser_for(klass, path)
    body = File.read(fixture(AUDIT_101_125_FIXTURE_ROOT, path))
    klass.new(Whois::Record::Part.new(body: body))
  end

  it 'keeps the exact source rows, including special-use and undelegated rows' do
    expect(AUDIT_101_125_TLDS.length).to eq(25)
    expect(AUDIT_101_125_TLDS).to eq(%w[
      apple zone top uz sa lan works gt systems lv bz so one ke hr md st ly
      business np am ge ba news et
    ])
    expect(AUDIT_101_125_TLDS & %w[
      invalid ne technology hn lu ma do mobi bd host tn li ec by kh nu tk ng
      global bo cr ir ve uy unifi
    ]).to be_empty
  end

  it 'retains the current hostname mapping for every query-capable source row' do
    expected_hosts = {
      apple: 'whois.afilias-srs.net',
      zone: 'whois.nic.zone',
      top: 'whois.nic.top',
      uz: 'whois.cctld.uz',
      sa: 'whois.nic.net.sa',
      lan: nil,
      works: 'whois.nic.works',
      gt: nil,
      systems: 'whois.nic.systems',
      lv: 'whois.nic.lv',
      bz: 'whois.afilias-grs.info',
      so: 'whois.nic.so',
      one: 'whois.nic.one',
      ke: 'whois.kenic.or.ke',
      hr: 'whois.dns.hr',
      md: 'whois.nic.md',
      st: 'whois.nic.st',
      ly: 'whois.nic.ly',
      business: 'whois.nic.business',
      np: nil,
      am: 'whois.amnic.net',
      ge: 'whois.registration.ge',
      ba: nil,
      news: 'whois.nic.news',
      et: nil,
    }

    expected_hosts.each do |tld, host|
      server = Whois::Server.find_for_domain("example.#{tld}")
      expect(server&.host).to eq(host), tld.to_s
    end
  end

  it 'does not turn observed unsupported denials into availability without a parser' do
    {
      'whois.afilias-srs.net' => 'whois.afilias-srs.net/apple/status_unsupported.txt',
      'whois.nic.zone' => 'whois.nic.zone/zone/status_unsupported.txt',
    }.each do |host, path|
      body = File.read(fixture(AUDIT_101_125_FIXTURE_ROOT, path))
      parser = Whois::Parsers::Blank.new(Whois::Record::Part.new(body: body, host: host))

      expect { parser.available? }.to raise_error(Whois::ParserNotFound)
      expect { parser.registered? }.to raise_error(Whois::ParserNotFound)
    end
  end

  describe 'reachable registries that deny the TLD' do
    {
      Whois::Parsers::WhoisNicWorks => 'whois.nic.works/works/status_unsupported.txt',
      Whois::Parsers::WhoisNicSystems => 'whois.nic.systems/systems/status_unsupported.txt',
      Whois::Parsers::WhoisNicBusiness => 'whois.nic.business/business/status_unsupported.txt',
      Whois::Parsers::WhoisNicNews => 'whois.nic.news/news/status_unsupported.txt',
    }.each do |klass, path|
      it "keeps #{klass} denial responses unavailable" do
        parser = parser_for(klass, path)

        expect(parser.response_unavailable?).to eq(true)
        expect { parser.status }.to raise_error(Whois::ResponseIsUnavailable)
        expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable)
        expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable)
      end
    end
  end

  describe Whois::Parsers::WhoisNicOne do
    it 'parses the current ICANN-shaped registered response' do
      parser = parser_for(described_class, 'whois.nic.one/one/status_registered.txt')

      expect(parser.status).to eq(:registered)
      expect(parser.available?).to eq(false)
      expect(parser.registered?).to eq(true)
    end

    it 'accepts the exact no-data response as availability evidence' do
      parser = parser_for(described_class, 'whois.nic.one/one/status_available.txt')

      expect(parser.status).to eq(:available)
      expect(parser.available?).to eq(true)
      expect(parser.registered?).to eq(false)
    end

    it 'does not infer registration from an unrecognised response' do
      parser = described_class.new(Whois::Record::Part.new(body: 'Temporary registry response'))

      expect(parser.status).to eq(:unknown)
      expect(parser.available?).to eq(false)
      expect(parser.registered?).to eq(false)
    end
  end

  describe Whois::Parsers::WhoisKenicOrKe do
    it 'accepts the current active status suffix' do
      parser = parser_for(described_class, 'whois.kenic.or.ke/ke/status_registered.txt')

      expect(parser.status).to eq(:registered)
      expect(parser.registered?).to eq(true)
      expect(parser.available?).to eq(false)
    end

    it 'accepts the current no-object absence marker' do
      parser = parser_for(described_class, 'whois.kenic.or.ke/ke/status_available.txt')

      expect(parser.status).to eq(:available)
      expect(parser.available?).to eq(true)
      expect(parser.registered?).to eq(false)
    end

    it 'does not infer registration from an unknown status' do
      parser = described_class.new(Whois::Record::Part.new(body: 'Status: registry-pending\n'))

      expect(parser.status).to eq(:unknown)
      expect(parser.available?).to eq(false)
      expect(parser.registered?).to eq(false)
    end
  end

  describe Whois::Parsers::WhoisDnsHr do
    it 'ignores the current percent-prefixed notice before registered data' do
      parser = parser_for(described_class, 'whois.dns.hr/hr/status_registered.txt')

      expect(parser.status).to eq(:registered)
      expect(parser.registered?).to eq(true)
      expect(parser.expires_on).to be_a(Time)
    end

    it 'accepts case-insensitive current absence wording' do
      parser = parser_for(described_class, 'whois.dns.hr/hr/status_available.txt')

      expect(parser.status).to eq(:available)
      expect(parser.available?).to eq(true)
      expect(parser.registered?).to eq(false)
    end

    it 'does not infer registration from an unrecognised response' do
      parser = described_class.new(Whois::Record::Part.new(body: 'Temporary registry response'))

      expect(parser.response_unavailable?).to eq(true)
      expect { parser.status }.to raise_error(Whois::ResponseIsUnavailable)
      expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable)
    end
  end

  describe Whois::Parsers::WhoisNicMd do
    it 'parses the current double-space domain label' do
      parser = parser_for(described_class, 'whois.nic.md/md/status_registered.txt')

      expect(parser.domain).to eq('example.md')
      expect(parser.status).to eq(:registered)
      expect(parser.registered?).to eq(true)
    end

    it 'requires the complete current no-match marker' do
      parser = parser_for(described_class, 'whois.nic.md/md/status_available.txt')

      expect(parser.status).to eq(:available)
      expect(parser.available?).to eq(true)
      expect(parser.registered?).to eq(false)
    end
  end

  describe Whois::Parsers::WhoisNicLy do
    it 'recognises the current no-object absence marker' do
      parser = parser_for(described_class, 'whois.nic.ly/ly/status_available.txt')

      expect(parser.status).to eq(:available)
      expect(parser.available?).to eq(true)
      expect(parser.registered?).to eq(false)
    end

    it 'does not classify an unrelated response as registered' do
      parser = described_class.new(Whois::Record::Part.new(body: 'Temporary registry response'))

      expect(parser.available?).to eq(false)
      expect(parser.registered?).to eq(false)
      expect(parser.status).to eq(:unknown)
    end
  end

  describe Whois::Parsers::WhoisAmnicNet do
    it 'accepts the current active status suffix' do
      parser = parser_for(described_class, 'whois.amnic.net/am/status_registered.txt')

      expect(parser.status).to eq(:registered)
      expect(parser.registered?).to eq(true)
      expect(parser.available?).to eq(false)
    end

    it 'keeps the exact no-match response available' do
      parser = parser_for(described_class, 'whois.amnic.net/am/status_available.txt')

      expect(parser.status).to eq(:available)
      expect(parser.available?).to eq(true)
      expect(parser.registered?).to eq(false)
    end

    it 'does not infer registration from an unknown response' do
      parser = described_class.new(Whois::Record::Part.new(body: 'Temporary registry response'))

      expect(parser.status).to eq(:unknown)
      expect(parser.registered?).to eq(false)
    end
  end
end
