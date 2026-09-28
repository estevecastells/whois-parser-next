require 'spec_helper'
require 'whois/parsers/whois.nic.uk'

# Current redacted record/absence/namespace samples were observed from
# whois.nic.uk:43 on 2026-09-29. The explicit denial fixture is synthetic,
# sourced from the DomScan integration guard. A separate synthetic record
# retains one short Nominet policy-banner sentence for the false-denial check;
# longer terms text is omitted because it is not parser evidence.
RSpec.describe Whois::Parsers::WhoisNicUk, 'Nominet response safety' do
  def parser_for_fixture(filename)
    body = File.read(fixture('responses', "whois.nic.uk/uk/#{filename}"))
    described_class.new(Whois::Record::Part.new(body: body))
  end

  def parser_for(body)
    described_class.new(Whois::Record::Part.new(body: body))
  end

  it 'keeps the current .co.uk registered shape' do
    parser = parser_for_fixture('registered_current_redacted.txt')

    expect(parser.status).to eq(:registered)
    expect(parser.available?).to eq(false)
    expect(parser.registered?).to eq(true)
    expect(parser.created_on).to eq(Time.parse('1999-02-14'))
    expect(parser.expires_on).to eq(Time.parse('2027-02-14'))
  end

  it 'does not mistake a short Nominet policy banner for a denial' do
    parser = parser_for_fixture('registered_policy_banner_synthetic.txt')

    expect(parser.response_unavailable?).to eq(false)
    expect(parser.status).to eq(:registered)
    expect(parser.registered?).to eq(true)
  end

  it 'recognizes the paired authoritative absence markers' do
    parser = parser_for_fixture('available_current_redacted.txt')

    expect(parser.status).to eq(:available)
    expect(parser.available?).to eq(true)
    expect(parser.registered?).to eq(false)
  end

  it 'keeps a response for a domain outside the .uk namespace unknown' do
    parser = parser_for_fixture('not_registry_current_redacted.txt')

    expect(parser.status).to eq(:unknown)
    expect(parser.available?).to eq(false)
    expect(parser.registered?).to eq(false)
  end

  it 'treats the explicit synthetic access denial as unavailable' do
    parser = parser_for_fixture('access_denied_synthetic.txt')

    expect(parser.response_unavailable?).to eq(true)
    expect { parser.status }.to raise_error(Whois::ResponseIsUnavailable)
  end

  it 'does not let a denial be hidden by registered or absent markers' do
    registered = File.read(fixture('responses', 'whois.nic.uk/uk/registered_current_redacted.txt'))
    absent = File.read(fixture('responses', 'whois.nic.uk/uk/available_current_redacted.txt'))
    denial = File.read(fixture('responses', 'whois.nic.uk/uk/access_denied_synthetic.txt'))

    [registered, absent].each do |evidence|
      parser = parser_for("#{evidence}\n#{denial}")
      expect(parser.response_unavailable?).to eq(true)
      expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable)
    end
  end

  it 'does not treat incomplete registered-looking responses as registrations' do
    partial = parser_for_fixture('registered_partial_synthetic.txt')
    domain_only = parser_for("Domain name: partial.co.uk\n")

    [partial, domain_only].each do |parser|
      expect(parser.status).to eq(:unknown)
      expect(parser.available?).to eq(false)
      expect(parser.registered?).to eq(false)
    end
  end

  it 'does not let record evidence turn absence markers into availability' do
    absent = File.read(fixture('responses', 'whois.nic.uk/uk/available_current_redacted.txt'))
    contradictory = parser_for("#{absent}\nDomain name: redacted-probe.co.uk\n")

    expect(contradictory.status).to eq(:unknown)
    expect(contradictory.available?).to eq(false)
    expect(contradictory.registered?).to eq(false)
  end

  it 'does not report invalid or reserved states as registered' do
    invalid = parser_for_fixture('status_invalid.txt')
    reserved = parser_for_fixture('status_reserved.txt')

    expect(invalid.status).to eq(:invalid)
    expect(invalid.registered?).to eq(false)
    expect(reserved.status).to eq(:reserved)
    expect(reserved.registered?).to eq(false)
  end

  it 'preserves Nominet quota detection' do
    parser = parser_for_fixture('response_throttled.txt')

    expect(parser.response_throttled?).to eq(true)
    expect { parser.status }.to raise_error(Whois::ResponseIsThrottled)
  end
end
