require 'spec_helper'
require 'whois/parsers/whois.nic.gives'

RSpec.describe Whois::Parsers::WhoisNicGives do
  # The registry's full response includes restrictive terms. Keep only the
  # public field shape in a synthetic fixture and test its exact absence line.
  def parse(body)
    described_class.new(Whois::Record::Part.new(body: body))
  end

  it 'resolves the IANA-listed WHOIS host to this parser' do
    expect(Whois::Server.find_for_domain('example.gives').host).to eq('whois.nic.gives')
    expect(Whois::Parser.parser_klass('whois.nic.gives')).to eq(described_class)
  end

  it 'parses a synthetic registered shape and the exact observed absence marker' do
    registered = parse(File.read(fixture('responses', 'whois.nic.gives/gives/status_registered_synthetic.txt')))
    available = parse(File.read(fixture('responses', 'whois.nic.gives/gives/status_available.txt')))

    expect(registered.domain).to eq('sample.gives')
    expect(registered.status).to eq(:registered)
    expect(registered.registered?).to eq(true)
    expect(registered.available?).to eq(false)
    expect(registered.nameservers.map(&:name)).to eq(%w[ns1.example.net ns2.example.net])

    expect(available.status).to eq(:available)
    expect(available.available?).to eq(true)
    expect(available.registered?).to eq(false)
  end

  it 'raises unavailable for denials and keeps malformed or contradictory replies unknown' do
    [
      'Access denied',
      'Permission denied',
      'Not authorised',
    ].each do |body|
      parser = parse(body)
      expect(parser.response_unavailable?).to eq(true)
      expect { parser.status }.to raise_error(Whois::ResponseIsUnavailable)
      expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable)
    end

    [
      'No Data Found',
      "Domain not found.\nDomain Name: sample.gives\nRegistrar: Example Registrar\n",
      "Domain not found.\nAccess denied\n",
      "Domain not found.\n% Access denied\n",
      'Domain Name: sample.gives',
      "Domain Name: sample.gives\nRegistrar: Example Registrar\n",
      "Domain Name: sample.example\nRegistrar: Example Registrar\n",
    ].each do |body|
      parser = parse(body)
      if parser.response_unavailable?
        expect { parser.status }.to raise_error(Whois::ResponseIsUnavailable)
        expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable)
      else
        expect(parser.status).to eq(:unknown)
        expect(parser.registered?).to eq(false)
        expect(parser.available?).to eq(false)
      end
    end
  end

  it 'does not let a rate-limit reply turn an absence marker into availability' do
    parser = parse("Domain not found.\nQuery rate limit exceeded\n")

    expect(parser.response_throttled?).to eq(true)
    expect { parser.available? }.to raise_error(Whois::ResponseIsThrottled)
  end
end
