require 'spec_helper'
require 'whois/parser'
require 'whois/parsers/whois.nic.open'

RSpec.describe Whois::Parsers::WhoisNicOpen do
  def parser_for_fixture(name)
    body = File.read(fixture('responses', 'whois.nic.open', 'open', name))
    parser_for_body(body)
  end

  def parser_for_body(body)
    Whois::Parser.parser_for(Whois::Record::Part.new(body: body, host: 'whois.nic.open'))
  end

  it 'is selected for the IANA-listed .open WHOIS host' do
    expect(Whois::Parser.parser_klass('whois.nic.open')).to eq(described_class)
  end

  it 'classifies a synthetic complete nic.open record as registered' do
    parser = parser_for_fixture('registered_synthetic.txt')

    expect(parser.domain).to eq('synthetic-record.open')
    expect(parser.domain_id).to eq('D000001-OPEN')
    expect(parser.status).to eq(:registered)
    expect(parser.registered?).to eq(true)
    expect(parser.available?).to eq(false)
    expect(parser.registrar.name).to eq('American Express Travel Related Services, Inc.')
    expect(parser.nameservers.map(&:name)).to eq(%w[ns1.example.invalid ns2.example.invalid])
    expect(parser.expires_on).to eq(Time.utc(2027, 1, 1, 0, 0, 0))
  end

  it 'keeps the observed No Data Found marker unknown under the restricted policy' do
    parser = parser_for_fixture('no_data_synthetic.txt')

    expect(parser.status).to eq(:unknown)
    expect(parser.available?).to eq(false)
    expect(parser.registered?).to eq(false)
  end

  it 'rejects No Data Found mixed with registry record evidence' do
    body = File.read(fixture('responses', 'whois.nic.open', 'open', 'no_data_synthetic.txt'))
    parser = parser_for_body("#{body}\nDomain Name: synthetic-record.open\n")

    expect(parser.response_unavailable?).to eq(true)
    expect { parser.status }.to raise_error(Whois::ResponseIsUnavailable)
    expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable)
    expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable)
  end

  it 'rejects a denial mixed with No Data Found' do
    body = File.read(fixture('responses', 'whois.nic.open', 'open', 'no_data_synthetic.txt'))
    parser = parser_for_body("#{body}\nAccess denied\n")

    expect(parser.response_unavailable?).to eq(true)
    expect { parser.status }.to raise_error(Whois::ResponseIsUnavailable)
    expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable)
    expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable)
  end

  it 'rejects a denial mixed with a registered record' do
    body = File.read(fixture(
      'responses', 'whois.nic.open', 'open', 'registered_synthetic.txt'
    ))
    parser = parser_for_body("#{body}\nAccess denied\n")

    expect(parser.response_unavailable?).to eq(true)
    expect { parser.status }.to raise_error(Whois::ResponseIsUnavailable)
  end

  it 'reports throttling instead of a classification when mixed with No Data Found' do
    body = File.read(fixture('responses', 'whois.nic.open', 'open', 'no_data_synthetic.txt'))
    parser = parser_for_body("#{body}\nToo many requests\n")

    expect(parser.response_throttled?).to eq(true)
    expect { parser.status }.to raise_error(Whois::ResponseIsThrottled)
    expect { parser.available? }.to raise_error(Whois::ResponseIsThrottled)
  end

  it 'keeps incomplete or non-.open record shapes unknown' do
    partial = parser_for_body("Domain Name: partial.open\nRegistry Domain ID: D000002-OPEN\n")
    wrong_suffix = parser_for_body(File.read(
      fixture('responses', 'whois.nic.open', 'open', 'registered_synthetic.txt')
    ).sub('Domain Name: synthetic-record.open', 'Domain Name: synthetic-record.example'))

    expect(partial.status).to eq(:unknown)
    expect(partial.registered?).to eq(false)
    expect(wrong_suffix.status).to eq(:unknown)
    expect(wrong_suffix.registered?).to eq(false)
  end
end
