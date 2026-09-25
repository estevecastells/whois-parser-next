require 'spec_helper'

require 'whois/parsers/whois.nic.africa'
require 'whois/parsers/whois.tld.mu'

RSpec.describe Whois::Parser, 'current IANA-listed WHOIS hosts in ranks 201-250' do
  def parser(klass, host, fixture_name)
    body = File.read(fixture(
      'responses', 'topdomains_201_250_current_20260925', host, "#{fixture_name}.txt"
    ))
    klass.new(Whois::Record::Part.new(body: body, host: host))
  end

  describe Whois::Parsers::WhoisTldMu do
    it 'parses the current registered record and exact absence marker' do
      registered = parser(described_class, 'whois.tld.mu', 'registered')
      available = parser(described_class, 'whois.tld.mu', 'available')

      expect(registered.status).to eq(:registered)
      expect(registered.domain).to eq('google.mu')
      expect(registered.nameservers.map(&:name)).to eq(%w[
        ns1.google.com ns4.google.com ns3.google.com ns2.google.com
      ])
      expect(registered.expires_on).to eq(Time.utc(2026, 12, 19, 13, 0, 0))
      expect(available.status).to eq(:available)
      expect(available.available?).to eq(true)
    end

    it 'keeps denials, throttling, and ambiguous replies from becoming status' do
      denied = described_class.new(
        Whois::Record::Part.new(body: 'Requests of this client are not permitted')
      )
      throttled = described_class.new(
        Whois::Record::Part.new(body: 'Query rate limit exceeded')
      )
      empty = described_class.new(Whois::Record::Part.new(body: " \n"))
      ambiguous = described_class.new(
        Whois::Record::Part.new(body: "Registry response pending\n")
      )

      expect { denied.status }.to raise_error(Whois::ResponseIsUnavailable)
      expect { throttled.status }.to raise_error(Whois::ResponseIsThrottled)
      expect { empty.status }.to raise_error(Whois::ResponseIsUnavailable)
      expect(ambiguous.status).to eq(:unknown)
      expect(ambiguous.available?).to eq(false)
      expect(ambiguous.registered?).to eq(false)
    end
  end

  describe Whois::Parsers::WhoisNicAfrica do
    it 'parses the current registered record and exact no-information marker' do
      registered = parser(described_class, 'whois.nic.africa', 'registered')
      available = parser(described_class, 'whois.nic.africa', 'available')

      expect(registered.status).to eq(:registered)
      expect(registered.domain).to eq('google.africa')
      expect(registered.nameservers.map(&:name)).to eq(%w[
        ns2.googledomains.com ns4.googledomains.com
        ns1.googledomains.com ns3.googledomains.com
      ])
      expect(registered.expires_on).to eq(Time.utc(2027, 6, 2, 22, 0, 29))
      expect(available.status).to eq(:available)
      expect(available.available?).to eq(true)
    end

    it 'keeps denials, throttling, and ambiguous replies from becoming status' do
      denied = described_class.new(
        Whois::Record::Part.new(body: 'Access to the WHOIS service is denied')
      )
      throttled = described_class.new(
        Whois::Record::Part.new(body: 'Maximum query rate reached')
      )
      empty = described_class.new(Whois::Record::Part.new(body: " \n"))
      ambiguous = described_class.new(
        Whois::Record::Part.new(body: "No matching details are available\n")
      )

      expect { denied.status }.to raise_error(Whois::ResponseIsUnavailable)
      expect { throttled.status }.to raise_error(Whois::ResponseIsThrottled)
      expect { empty.status }.to raise_error(Whois::ResponseIsUnavailable)
      expect(ambiguous.status).to eq(:unknown)
      expect(ambiguous.available?).to eq(false)
      expect(ambiguous.registered?).to eq(false)
    end
  end
end
