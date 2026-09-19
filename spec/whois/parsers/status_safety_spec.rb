require 'spec_helper'
require 'whois/parsers/base_nic_fr'
require 'whois/parsers/whois.domain-registry.nl'
require 'whois/parsers/whois.dotgov.gov'
require 'whois/parsers/whois.afilias-srs.net'
require 'whois/parsers/whois.afilias.net'
require 'whois/parsers/whois.registry.qa'
require 'whois/parsers/whois.kg'
require 'whois/parsers/whois.nic.ci'
require 'whois/parsers/whois.tznic.or.tz'
require 'whois/parsers/whois.cctld.uz'
require 'whois/parsers/whois.nic.net.sa'
require 'whois/parsers/whois.nic.lv'
require 'whois/parsers/whois.nic.md'
require 'whois/parsers/whois.nic.st'
require 'whois/parsers/whois.registre.ma'
require 'whois/parsers/whois.co.ug'
require 'whois/parsers/whois.nic.sn'
require 'whois/parsers/whois.nic.ac'
require 'whois/parsers/whois.nic.dz'
require 'whois/parsers/whois.nic.tm'
require 'whois/parsers/whois.nic.mw'
require 'whois/parsers/whois.nic.vip'
require 'whois/parsers/whois.zicta.zm'
require 'whois/parsers/whois.nic.sl'
require 'whois/parsers/whois.nic.fun'
require 'whois/parsers/whois.nic.ink'

RSpec.describe Whois::Parsers::Base, 'parser status safety' do
  def parser_for(klass, body)
    klass.new(Whois::Record::Part.new(body: body))
  end

  describe Whois::Parsers::BaseNicFr do
    it 'keeps an unrecognised response unknown instead of treating it as available or registered' do
      parser = parser_for(described_class, "%% Request denied by the registry.\n")

      expect(parser.status).to eq(:unknown)
      expect(parser.available?).to eq(false)
      expect(parser.registered?).to eq(false)
    end
  end

  describe Whois::Parsers::WhoisDomainRegistryNl do
    {
      'free' => :available,
      'withdrawn' => :reserved,
      'excluded' => :reserved,
      'requested' => :registered,
    }.each do |registry_status, expected_status|
      it "maps the documented #{registry_status} status" do
        parser = parser_for(described_class, "Status: #{registry_status.upcase}\n")

        expect(parser.status).to eq(expected_status)
      end
    end
  end

  describe Whois::Parsers::WhoisDotgovGov do
    it 'recognises a lower-case domain name label as registered evidence' do
      parser = parser_for(described_class, "domain name: gsa.gov\n")

      expect(parser.status).to eq(:registered)
      expect(parser.registered?).to eq(true)
      expect(parser.available?).to eq(false)
    end
  end

  describe 'registry responses without a record' do
    {
      Whois::Parsers::WhoisAfiliasSrsNet => <<~RESPONSE,
        TLD is not supported.
        >>> Last update of WHOIS database: 2026-09-19T00:56:24Z <<<

        Terms of Use: Access to WHOIS information is provided for query-based access.
      RESPONSE
      Whois::Parsers::WhoisRegistryQa => '',
      Whois::Parsers::WhoisKg => '',
      Whois::Parsers::WhoisNicCi => '',
      Whois::Parsers::WhoisAfiliasNet => '',
    }.each do |klass, body|
      it "does not infer registration for #{klass} from an unusable response" do
        parser = parser_for(klass, body)

        expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable)
      end
    end

    it 'keeps unknown whoisd and registry responses out of registered' do
      {
        Whois::Parsers::WhoisTznicOrTz => "domain: example.tz\n",
        Whois::Parsers::WhoisKg => 'Temporary registry response',
        Whois::Parsers::WhoisNicCi => 'Temporary registry response',
      }.each do |klass, body|
        parser = parser_for(klass, body)

        expect(parser.status).to eq(:unknown)
        expect(parser.registered?).to eq(false)
      end
    end

    it 'does not classify an empty .tz response as available or registered' do
      parser = parser_for(Whois::Parsers::WhoisTznicOrTz, '')

      expect { parser.status }.to raise_error(Whois::ResponseIsUnavailable)
      expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable)
    end

    it 'reports an unknown whoisd status without masking it with a NameError' do
      parser = parser_for(Whois::Parsers::WhoisTznicOrTz, "status: registry-pending\n")

      expect { parser.status }.to raise_error(Whois::ParserError, /registry-pending/)
    end

    [
      Whois::Parsers::WhoisCctldUz,
      Whois::Parsers::WhoisNicNetSa,
      Whois::Parsers::WhoisNicLv,
      Whois::Parsers::WhoisNicMd,
      Whois::Parsers::WhoisNicSt,
      Whois::Parsers::WhoisRegistreMa,
      Whois::Parsers::WhoisKg,
      Whois::Parsers::WhoisCoUg,
      Whois::Parsers::WhoisNicCi,
      Whois::Parsers::WhoisNicSn,
      Whois::Parsers::WhoisNicAc,
      Whois::Parsers::WhoisNicDz,
      Whois::Parsers::WhoisNicTm,
      Whois::Parsers::WhoisNicMw,
      Whois::Parsers::WhoisNicVip,
      Whois::Parsers::WhoisZictaZm,
      Whois::Parsers::WhoisNicSl,
      Whois::Parsers::WhoisNicFun,
      Whois::Parsers::WhoisNicInk,
    ].each do |klass|
      it "does not infer registration from an empty #{klass} response" do
        parser = parser_for(klass, '')

        expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable)
      end
    end
  end
end
