require 'spec_helper'
require 'whois/parsers/whois.tonicregistry.to'

RSpec.describe Whois::Parsers::WhoisTonicregistryTo do
  def parser_for(fixture_name)
    body = File.read(fixture('responses', 'whois.tonicregistry.to', 'to', fixture_name))
    parser_for_body(body)
  end

  def parser_for_body(body)
    described_class.new(Whois::Record::Part.new(body: body, host: 'whois.tonicregistry.to'))
  end

  it 'is selected for the IANA-listed official WHOIS host' do
    expect(Whois::Parser.parser_klass('whois.tonicregistry.to')).to eq(described_class)
  end

  it 'classifies a synthetic registered registry record' do
    parser = parser_for('registered_synthetic.txt')

    expect(parser.domain).to eq('synthetic.to')
    expect(parser.domain_id).to eq('SYNTHETIC-TONIC-1')
    expect(parser.status).to eq(:registered)
    expect(parser.registered?).to eq(true)
    expect(parser.available?).to eq(false)
    expect(parser.nameservers.map(&:name)).to eq(%w[ns1.example.invalid ns2.example.invalid])
  end

  it 'classifies a synthetic exact availability marker' do
    parser = parser_for('available_synthetic.txt')

    expect(parser.status).to eq(:available)
    expect(parser.available?).to eq(true)
    expect(parser.registered?).to eq(false)
  end

  it 'keeps an availability marker mixed with a record unavailable' do
    parser = parser_for('ambiguous_absence_with_record_synthetic.txt')

    expect(parser.response_unavailable?).to eq(true)
    expect { parser.status }.to raise_error(Whois::ResponseIsUnavailable)
    expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable)
    expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable)
  end

  it 'does not accept availability when any registry status field is present' do
    body = File.read(fixture(
      'responses', 'whois.tonicregistry.to', 'to', 'available_synthetic.txt'
    ))
    parser = parser_for_body("#{body}\nDomain Status: clientTransferProhibited\n")

    expect(parser.response_unavailable?).to eq(true)
    expect { parser.status }.to raise_error(Whois::ResponseIsUnavailable)
  end

  it 'keeps generic denial and throttling mixed with availability unknown' do
    available_body = File.read(fixture(
      'responses', 'whois.tonicregistry.to', 'to', 'available_synthetic.txt'
    ))
    denied = parser_for_body("#{available_body}\nAccess denied\n")
    throttled = parser_for_body("#{available_body}\nToo many requests\n")

    expect(denied.response_unavailable?).to eq(true)
    expect { denied.status }.to raise_error(Whois::ResponseIsUnavailable)
    expect(throttled.response_throttled?).to eq(true)
    expect { throttled.status }.to raise_error(Whois::ResponseIsThrottled)
  end

  it 'leaves an incomplete registered-shaped body unknown' do
    parser = parser_for_body("Domain Name: partial.to\nCreation Date: not-a-date\n")

    expect(parser.status).to eq(:unknown)
    expect(parser.registered?).to eq(false)
    expect(parser.available?).to eq(false)
  end
end
