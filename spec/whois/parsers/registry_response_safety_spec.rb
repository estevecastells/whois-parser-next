require 'spec_helper'

require 'whois/parsers/whois.nic.cloud'
require 'whois/parsers/whois.nic.club'
require 'whois/parsers/whois.nic.tv'
require 'whois/parsers/whois.nixiregistry.in'
require 'whois/parsers/whois.tonic.to'
require 'whois/parsers/whois.trabis.gov.tr'
require 'whois/parsers/whois.nic.tech'
require 'whois/parsers/whois.website.ws'
require 'whois/parsers/whois.sgnic.sg'
require 'whois/parsers/whois.sk-nic.sk'
require 'whois/parsers/whois.srs.net.nz'

RSpec.describe Whois::Parsers::Base, 'registry response safety' do
  def parser_for(klass, body)
    klass.new(Whois::Record::Part.new(body: body))
  end

  [
    Whois::Parsers::WhoisNicCloud,
    Whois::Parsers::WhoisNicClub,
    Whois::Parsers::WhoisNicTv,
    Whois::Parsers::WhoisNixiregistryIn,
  ].each do |klass|
    describe klass do
      it 'does not turn an empty response into a registration' do
        parser = parser_for(klass, '')

        expect(parser.response_incomplete?).to eq(true)
        expect(parser.response_unavailable?).to eq(true)
        expect { parser.status }.to raise_error(Whois::ResponseIsUnavailable)
      end

      it 'raises a typed error for a client denial' do
        parser = parser_for(klass, 'Access to the WHOIS service is denied.')

        expect(parser.response_unavailable?).to eq(true)
        expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable)
      end

      it 'raises a typed error for an explicit query throttle' do
        parser = parser_for(klass, 'WHOIS query rate limit exceeded.')

        expect(parser.response_throttled?).to eq(true)
        expect { parser.available? }.to raise_error(Whois::ResponseIsThrottled)
      end
    end
  end

  describe Whois::Parsers::WhoisTonicTo do
    it 'keeps an empty response incomplete and non-registered' do
      parser = parser_for(described_class, '')

      expect(parser.status).to eq(:incomplete)
      expect(parser.registered?).to eq(false)
    end

    it 'does not treat a denial or throttle response as a registration' do
      denial = parser_for(described_class, 'Requests of this client are not permitted.')
      throttled = parser_for(described_class, 'Maximum query rate reached.')

      expect { denial.registered? }.to raise_error(Whois::ResponseIsUnavailable)
      expect { throttled.registered? }.to raise_error(Whois::ResponseIsThrottled)
    end
  end

  describe Whois::Parsers::WhoisTrabisGovTr do
    it 'does not infer registration from an empty or unrecognised response' do
      empty = parser_for(described_class, '')
      unknown = parser_for(described_class, 'Temporary registry response')

      expect { empty.status }.to raise_error(Whois::ResponseIsUnavailable)
      expect(unknown.status).to eq(:unknown)
      expect(unknown.registered?).to eq(false)
    end
  end

  describe Whois::Parsers::WhoisNicTech do
    it 'requires the complete Radix availability marker' do
      expect(parser_for(described_class, '>>> Domain example.tech is available for registration').available?).to eq(true)
      expect(parser_for(described_class, '>>> Domain example.tech is available for registration now').available?).to eq(false)
    end
  end

  describe Whois::Parsers::WhoisWebsiteWs do
    it 'requires an exact availability response line' do
      expect(parser_for(described_class, 'No match for "example.ws".').available?).to eq(true)
      expect(parser_for(described_class, 'No match for "example.ws" because of a timeout').available?).to eq(false)
      expect(parser_for(described_class, 'The queried object does not exist: example.ws.').available?).to eq(true)
    end
  end

  describe Whois::Parsers::WhoisSgnicSg do
    it 'requires an exact SGNIC not-found marker' do
      expect(parser_for(described_class, 'Domain Not Found').available?).to eq(true)
      expect(parser_for(described_class, 'Not found: example.sg').available?).to eq(true)
      expect(parser_for(described_class, 'Not found: example.sg due to a server error').available?).to eq(false)
    end
  end

  describe Whois::Parsers::WhoisSkNicSk do
    it 'keeps an unknown domain status out of registered' do
      parser = parser_for(described_class, "Domain Status: registry changed\n")

      expect(parser.status).to eq(:unknown)
      expect(parser.available?).to eq(false)
      expect(parser.registered?).to eq(false)
    end
  end

  describe Whois::Parsers::WhoisSrsNetNz do
    it 'requires status evidence before treating a Domain Name line as active' do
      parser = parser_for(described_class, "Domain Name: example.co.nz\n")

      expect(parser.status).to eq(:unknown)
      expect(parser.registered?).to eq(false)
    end

    it 'still accepts the current fallback response with Domain Status evidence' do
      parser = parser_for(described_class, "Domain Name: example.co.nz\nDomain Status: clientDeleteProhibited\n")

      expect(parser.status).to eq(:registered)
      expect(parser.registered?).to eq(true)
    end
  end
end
