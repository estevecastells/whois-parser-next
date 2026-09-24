require 'csv'
require 'spec_helper'

require 'whois/parsers/whois.nic.cyou'
require 'whois/parsers/whois.nic.radio'
require 'whois/parsers/whois.nic.security'
require 'whois/parsers/whois.nic.xn--d1acj3b'
require 'whois/parsers/whois.nic.eco'
require 'whois/parsers/whois.nic.kiwi'
require 'whois/parsers/whois.nic.xn--tckwe'
require 'whois/parsers/whois.nic.solar'
require 'whois/parsers/whois.nic.maison'
require 'whois/parsers/whois.nic.tienda'
require 'whois/parsers/whois.nic.okinawa'

RSpec.describe Whois::Parser, 'top-1000 parser package 1 adapters' do
  it 'documents every assigned planning row exactly once' do
    planning = CSV.read(
      File.expand_path('../../../docs/audits/data/whois-parser-top1000-planning.csv', __dir__),
      headers: true
    ).select { |row| row['implementation_package'] == 'package-1' }
    audit = File.read(
      File.expand_path('../../../docs/audits/whois-parser-top1000-package-1-2026-09-19.md', __dir__)
    )

    planning_keys = planning.map { |row| "#{row['source_rank']}:#{row['tld']}" }
    audit_keys = audit.scan(/\b(\d+:[a-z0-9-]+)\b/).flatten

    expect(audit_keys).to match_array(planning_keys)
  end

  def parser_for(klass, host, fixture_name)
    body = File.read(fixture('responses', 'top1000_package1', host, fixture_name))
    klass.new(Whois::Record::Part.new(body: body, host: host))
  end

  {
    Whois::Parsers::WhoisNicCyou => 'whois.nic.cyou',
    Whois::Parsers::WhoisNicRadio => 'whois.nic.radio',
    Whois::Parsers::WhoisNicSecurity => 'whois.nic.security',
    Whois::Parsers::WhoisNicXnD1acj3b => 'whois.nic.xn--d1acj3b',
  }.each do |klass, host|
    describe klass do
      it 'classifies the authoritative registered response' do
        parser = parser_for(klass, host, 'status_registered.txt')

        expect(parser.registered?).to eq(true)
        expect(parser.available?).to eq(false)
        expect(parser.domain).to match(/\A(?:google|nic)\./i)
      end

      it 'classifies the authoritative absence response as available' do
        parser = parser_for(klass, host, 'status_available.txt')

        expect(parser.available?).to eq(true)
        expect(parser.registered?).to eq(false)
      end
    end
  end

  {
    Whois::Parsers::WhoisNicEco => 'whois.nic.eco',
    Whois::Parsers::WhoisNicKiwi => 'whois.nic.kiwi',
  }.each do |klass, host|
    describe klass do
      it 'classifies the authoritative CIRA registered response' do
        parser = parser_for(klass, host, 'status_registered.txt')

        expect(parser.registered?).to eq(true)
        expect(parser.available?).to eq(false)
      end

      it 'classifies the authoritative CIRA absence response as available' do
        parser = parser_for(klass, host, 'status_available.txt')

        expect(parser.available?).to eq(true)
        expect(parser.registered?).to eq(false)
      end
    end
  end

  describe Whois::Parsers::WhoisNicXnTckwe do
    it 'classifies the authoritative VeriSign registered response' do
      parser = parser_for(described_class, 'whois.nic.xn--tckwe', 'status_registered.txt')

      expect(parser.registered?).to eq(true)
      expect(parser.available?).to eq(false)
    end

    it 'classifies the authoritative VeriSign absence response as available' do
      parser = parser_for(described_class, 'whois.nic.xn--tckwe', 'status_available.txt')

      expect(parser.available?).to eq(true)
      expect(parser.registered?).to eq(false)
    end
  end

  {
    Whois::Parsers::WhoisNicSolar => 'whois.nic.solar',
    Whois::Parsers::WhoisNicMaison => 'whois.nic.maison',
    Whois::Parsers::WhoisNicTienda => 'whois.nic.tienda',
  }.each do |klass, host|
    it "keeps the explicit unsupported response unavailable for #{host}" do
      parser = parser_for(klass, host, 'unsupported.txt')

      expect(parser.response_unavailable?).to eq(true)
      expect { parser.status }.to raise_error(Whois::ResponseIsUnavailable)
      expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable)
      expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable)
    end
  end

  it 'keeps the retired .okinawa WHOIS endpoint unavailable' do
    parser = parser_for(Whois::Parsers::WhoisNicOkinawa, 'whois.nic.okinawa', 'retired.txt')

    expect(parser.response_unavailable?).to eq(true)
    expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable)
    expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable)
  end

  [
    Whois::Parsers::WhoisNicCyou,
    Whois::Parsers::WhoisNicRadio,
    Whois::Parsers::WhoisNicSecurity,
    Whois::Parsers::WhoisNicXnD1acj3b,
    Whois::Parsers::WhoisNicEco,
    Whois::Parsers::WhoisNicKiwi,
    Whois::Parsers::WhoisNicXnTckwe,
  ].each do |klass|
    it "does not infer a result from an empty #{klass} response" do
      parser = klass.new(Whois::Record::Part.new(body: File.read(fixture('responses', 'top1000_package1/safety/empty.txt'))))

      expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable)
      expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable)
    end

    it "does not infer a result from a denied #{klass} response" do
      parser = klass.new(Whois::Record::Part.new(body: File.read(fixture('responses', 'top1000_package1/safety/denied.txt'))))

      expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable)
      expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable)
    end

    it "keeps an ambiguous #{klass} response unknown" do
      parser = klass.new(Whois::Record::Part.new(body: File.read(fixture('responses', 'top1000_package1/safety/ambiguous.txt'))))

      expect(parser.status).to eq(:unknown)
      expect(parser.available?).to eq(false)
      expect(parser.registered?).to eq(false)
    end
  end
end
