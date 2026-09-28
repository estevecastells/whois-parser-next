require 'spec_helper'
require 'whois/parsers/whois.nic.mn'

RSpec.describe Whois::Parsers::WhoisNicMn do
  # The registry's full response includes restrictive terms; this fixture is
  # a synthetic field-shape sample without source values or footer text.
  def parse(body)
    described_class.new(Whois::Record::Part.new(body: body))
  end

  it 'resolves the current registry host to this parser' do
    expect(Whois::Server.find_for_domain('example.mn').host).to eq('whois.nic.mn')
    expect(Whois::Parser.parser_klass('whois.nic.mn')).to eq(described_class)
  end

  it 'recognizes a synthetic registered shape and the observed absent .mn marker' do
    registered_body = File.read(fixture('responses', 'whois.nic.mn/mn/registered_synthetic.txt'))
    registered = parse(registered_body)
    available = parse(File.read(fixture('responses', 'whois.nic.mn/mn/available.txt')))

    expect(registered.status).to eq(:registered)
    expect(registered.domain).to eq('sample.mn')
    expect(registered.registered?).to eq(true)
    expect(registered.nameservers.map(&:name)).to eq(%w[ns1.example.net ns2.example.net])
    expect(available.status).to eq(:available)
    expect(available.available?).to eq(true)

    crlf_registered = parse(registered_body.gsub("\n", "\r\n"))
    crlf_available = parse("Domain not found.\r\n")
    expect(crlf_registered.status).to eq(:registered)
    expect(crlf_available.status).to eq(:available)
  end

  it 'raises unavailable for denials and keeps incomplete or contradictory replies unknown' do
    [
      'Access denied',
      'Permission denied',
      'Not authorised',
      "Access denied\nDomain not found.\n",
      "Domain not found.\nAccess denied\n",
      "Domain not found.\n% Access denied\n",
    ].each do |body|
      parser = parse(body)
      expect(parser.response_unavailable?).to eq(true)
      expect { parser.status }.to raise_error(Whois::ResponseIsUnavailable)
      expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable)
    end

    [
      'Domain Name: sample.mn',
      "Domain Name: sample.mn\nRegistrar: Example Registrar\n",
      "Domain not found.\nDomain Name: sample.mn\nRegistrar: Registry\n",
    ].each do |body|
      parser = parse(body)
      expect(parser.status).to eq(:unknown)
      expect(parser.registered?).to eq(false)
      expect(parser.available?).to eq(false)
    end
  end

  it 'does not let a rate-limit reply turn an absence marker into availability' do
    parser = parse("Domain not found.\nQuery rate limit exceeded\n")

    expect(parser.response_throttled?).to eq(true)
    expect { parser.available? }.to raise_error(Whois::ResponseIsThrottled)
  end
end
