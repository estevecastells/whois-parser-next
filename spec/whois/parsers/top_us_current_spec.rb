require 'spec_helper'

require 'whois/parsers/whois.nic.top'
require 'whois/parsers/whois.nic.us'

RSpec.describe Whois::Parser, 'current .top and .us WHOIS evidence' do
  def parser_for(klass, body)
    klass.new(Whois::Record::Part.new(body: body))
  end

  def fixture_body(path)
    File.read(fixture('responses', path))
  end

  it 'loads the official WHOIS host parsers for both TLDs' do
    {
      'top' => ['whois.nic.top', Whois::Parsers::WhoisNicTop],
      'us' => ['whois.nic.us', Whois::Parsers::WhoisNicUs],
    }.each do |tld, (host, parser_class)|
      server = Whois::Server.find_for_domain("google.#{tld}")

      expect(server.host).to eq(host)
      expect(described_class.parser_klass(host)).to eq(parser_class)
    end
  end

  describe Whois::Parsers::WhoisNicTop do
    it 'parses the current registered ICANN-shaped response' do
      parser = parser_for(described_class, fixture_body('whois.nic.top/top/status_registered_current.txt'))

      expect(parser.domain).to eq('google.top')
      expect(parser.status).to eq(:registered)
      expect(parser.registered?).to eq(true)
      expect(parser.available?).to eq(false)
      expect(parser.domain_id).to eq('D20150409G10001G_34600327-top')
      expect(parser.registrar.name).to eq('MarkMonitor')
      expect(parser.nameservers.map(&:name)).to contain_exactly(
        'ns1.google.com', 'ns2.google.com', 'ns3.google.com', 'ns4.google.com'
      )
    end

    it 'accepts only the exact current object-absence line' do
      parser = parser_for(described_class, fixture_body('whois.nic.top/top/status_absent_current.txt'))

      expect(parser.status).to eq(:available)
      expect(parser.available?).to eq(true)
      expect(parser.registered?).to eq(false)
    end

    it 'does not interpret a malformed object-absence line as availability' do
      parser = parser_for(described_class, fixture_body('whois.nic.top/top/unknown_marker.txt'))

      expect(parser.status).to eq(:unknown)
      expect(parser.available?).to eq(false)
      expect(parser.registered?).to eq(false)
    end
  end

  describe Whois::Parsers::WhoisNicUs do
    it 'requires current domain-name and EPP status evidence for registration' do
      parser = parser_for(described_class, fixture_body('whois.nic.us/us/status_registered_current.txt'))

      expect(parser.domain).to eq('google.us')
      expect(parser.status.map { |value| value.split.first }).to contain_exactly(
        'clientTransferProhibited', 'clientDeleteProhibited', 'clientUpdateProhibited',
        'serverUpdateProhibited', 'serverDeleteProhibited', 'serverTransferProhibited'
      )
      expect(parser.registered?).to eq(true)
      expect(parser.available?).to eq(false)
    end

    it 'keeps current and legacy no-record responses unknown because the registry disclaims availability' do
      [
        fixture_body('whois.nic.us/us/status_no_record_current.txt'),
        fixture_body('whois.nic.us/us/status_available.txt'),
      ].each do |body|
        parser = parser_for(described_class, body)

        expect(parser.status).to eq(:unknown)
        expect(parser.available?).to eq(false)
        expect(parser.registered?).to eq(false)
      end
    end

    it 'does not infer registration from a domain-name line without registry status evidence' do
      parser = parser_for(described_class, "Domain Name: example.us\n")

      expect(parser.status).to eq(:unknown)
      expect(parser.registered?).to eq(false)
      expect(parser.available?).to eq(false)
    end

    it 'does not treat a non-EPP status label as registration evidence' do
      parser = parser_for(described_class, "Domain Name: example.us\nDomain Status: Reserved\n")

      expect(parser.status).to eq(:unknown)
      expect(parser.registered?).to eq(false)
      expect(parser.available?).to eq(false)
    end
  end

  [
    Whois::Parsers::WhoisNicTop,
    Whois::Parsers::WhoisNicUs,
  ].each do |parser_class|
    describe parser_class do
      it 'rejects empty responses as unavailable' do
        parser = parser_for(parser_class, '')

        expect { parser.status }.to raise_error(Whois::ResponseIsUnavailable)
        expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable)
      end

      it 'rejects denied responses as unavailable' do
        parser = parser_for(parser_class, 'Access to the WHOIS service is denied.')

        expect { parser.status }.to raise_error(Whois::ResponseIsUnavailable)
        expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable)
      end

      it 'rejects throttled responses instead of making a domain classification' do
        parser = parser_for(parser_class, 'WHOIS query rate limit exceeded.')

        expect { parser.status }.to raise_error(Whois::ResponseIsThrottled)
        expect { parser.available? }.to raise_error(Whois::ResponseIsThrottled)
        expect { parser.registered? }.to raise_error(Whois::ResponseIsThrottled)
      end
    end
  end
end
