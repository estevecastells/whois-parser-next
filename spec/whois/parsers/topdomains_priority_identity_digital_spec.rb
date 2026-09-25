require 'spec_helper'

require 'whois/parsers/whois.nic.media'
require 'whois/parsers/whois.nic.services'
require 'whois/parsers/whois.nic.network'
require 'whois/parsers/whois.nic.live'
require 'whois/parsers/whois.nic.digital'
require 'whois/parsers/whois.nic.email'

IDENTITY_DIGITAL_UNSUPPORTED_MAPPINGS = {
  'media' => ['whois.nic.media', Whois::Parsers::WhoisNicMedia],
  'services' => ['whois.nic.services', Whois::Parsers::WhoisNicServices],
  'network' => ['whois.nic.network', Whois::Parsers::WhoisNicNetwork],
  'live' => ['whois.nic.live', Whois::Parsers::WhoisNicLive],
  'digital' => ['whois.nic.digital', Whois::Parsers::WhoisNicDigital],
  'email' => ['whois.nic.email', Whois::Parsers::WhoisNicEmail],
}.freeze

RSpec.describe Whois::Parser, 'Identity Digital unsupported TLD responses' do
  def parser_for(host, body)
    parser_class = described_class.parser_klass(host)
    parser_class.new(Whois::Record::Part.new(body: body, host: host))
  end

  it 'retains the current server mapping and explicit unavailable adapter for each TLD' do
    IDENTITY_DIGITAL_UNSUPPORTED_MAPPINGS.each do |tld, (host, klass)|
      expect(Whois::Server.find_for_domain("google.#{tld}").host).to eq(host), tld
      expect(described_class.parser_klass(host)).to eq(klass), tld
    end
  end

  it 'marks the exact unsupported response unavailable without claiming status' do
    response = File.read(fixture('responses', 'topdomains_priority/identity_digital_unsupported.txt'))

    IDENTITY_DIGITAL_UNSUPPORTED_MAPPINGS.each_value do |host, _klass|
      parser = parser_for(host, response)

      expect(parser).to be_a(Whois::Parsers::BaseUnsupportedRegistry), host
      expect(parser.response_unavailable?).to eq(true), host
      expect { parser.status }.to raise_error(Whois::ResponseIsUnavailable), host
      expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable), host
      expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable), host
    end
  end

  it 'keeps a footer without the denial, an empty response, and unrelated text unknown' do
    responses = [
      ">>> Last update of WHOIS database: 2026-09-25T11:48:28Z <<<\nTerms of Use:\n",
      '',
      'Temporary registry response',
    ]

    IDENTITY_DIGITAL_UNSUPPORTED_MAPPINGS.each_value do |host, _klass|
      responses.each do |body|
        parser = parser_for(host, body)

        expect(parser.response_unavailable?).to eq(false), host
        expect(parser.status).to eq(:unknown), host
        expect(parser.available?).to eq(false), host
        expect(parser.registered?).to eq(false), host
      end
    end
  end
end
