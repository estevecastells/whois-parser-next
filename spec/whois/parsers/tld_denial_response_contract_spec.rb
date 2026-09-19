require 'spec_helper'
require 'whois/parsers/whois.domainregistry.ie'
require 'whois/parsers/whois.mynic.my'
require 'whois/parsers/whois.nic.online'
require 'whois/parsers/whois.nic.site'

RSpec.describe Whois::Parsers::Base, 'TLD denial response contracts' do
  def parser_for(klass, body)
    klass.new(Whois::Record::Part.new(body: body))
  end

  describe 'Radix .online and .site responses' do
    it 'requires the exact .online availability marker' do
      parser = parser_for(
        Whois::Parsers::WhoisNicOnline,
        'NOTICE: Domain example.online is available for registration'
      )

      expect(parser.available?).to eq(false)
    end

    it 'treats a reserved .site name as registered but unavailable' do
      parser = parser_for(Whois::Parsers::WhoisNicSite, '>>> Domain name is registry reserved')

      expect(parser.status).to eq(:reserved)
      expect(parser.available?).to eq(false)
      expect(parser.registered?).to eq(true)
    end

    [
      [Whois::Parsers::WhoisNicOnline, 'WHOIS query rate limit exceeded. Try again later.'],
      [Whois::Parsers::WhoisNicSite, 'Maximum query rate reached. Please try again later.'],
    ].each do |klass, body|
      it "raises a typed throttle error for #{klass}" do
        parser = parser_for(klass, body)

        expect(parser.response_throttled?).to eq(true)
        expect { parser.available? }.to raise_error(Whois::ResponseIsThrottled)
        expect { parser.registered? }.to raise_error(Whois::ResponseIsThrottled)
      end
    end

    [Whois::Parsers::WhoisNicOnline, Whois::Parsers::WhoisNicSite].each do |klass|
      it "raises a typed unavailable error for a denied #{klass} response" do
        parser = parser_for(klass, 'Requests of this client are not permitted.')

        expect(parser.response_unavailable?).to eq(true)
        expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable)
        expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable)
      end
    end
  end

  describe '.my responses' do
    it 'does not treat the normal query-limit footer as throttling' do
      parser = parser_for(
        Whois::Parsers::WhoisMynicMy,
        "Please note that the query limit is 500 per day from the same IP.\n\n" \
        'Domain Name [u34jedzcq.my] does not exist in database'
      )

      expect(parser.response_throttled?).to eq(false)
      expect(parser.available?).to eq(true)
    end

    it 'raises a typed throttle error for an explicit daily limit failure' do
      parser = parser_for(Whois::Parsers::WhoisMynicMy, 'You have exceeded your daily query limit.')

      expect(parser.response_throttled?).to eq(true)
      expect { parser.available? }.to raise_error(Whois::ResponseIsThrottled)
      expect { parser.registered? }.to raise_error(Whois::ResponseIsThrottled)
    end

    it 'raises a typed unavailable error for a denied response' do
      parser = parser_for(Whois::Parsers::WhoisMynicMy, 'Access to the WHOIS service is denied.')

      expect(parser.response_unavailable?).to eq(true)
      expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable)
      expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable)
    end
  end

  describe '.ie daily-limit wording' do
    it 'recognizes daily query limit wording in either order' do
      [
        'You have reached your daily limit.',
        'You have exceeded your daily query limit.',
        'Daily query limit exceeded.',
      ].each do |body|
        parser = parser_for(Whois::Parsers::WhoisDomainregistryIe, body)

        expect(parser.response_throttled?).to eq(true), body
        expect { parser.available? }.to raise_error(Whois::ResponseIsThrottled), body
        expect { parser.registered? }.to raise_error(Whois::ResponseIsThrottled), body
      end
    end
  end
end
