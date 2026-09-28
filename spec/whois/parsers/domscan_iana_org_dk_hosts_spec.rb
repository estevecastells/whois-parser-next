require 'spec_helper'
require 'whois/parsers/whois.publicinterestregistry.org'
require 'whois/parsers/whois.punktum.dk'

RSpec.describe Whois::Parsers::WhoisPublicinterestregistryOrg, 'IANA current .org and .dk WHOIS hosts' do
  def parse(klass, body, host)
    klass.new(Whois::Record::Part.new(body: body, host: host))
  end

  def fixture_body(path)
    File.read(fixture('responses', path))
  end

  let(:org_registered) do
    fixture_body('whois.publicinterestregistry.org/org/registered_redacted.txt')
  end
  let(:org_available) do
    fixture_body('whois.publicinterestregistry.org/org/available.txt')
  end
  let(:dk_registered) do
    fixture_body('whois.punktum.dk/dk/registered_redacted.txt')
  end
  let(:dk_available) do
    fixture_body('whois.punktum.dk/dk/available.txt')
  end

  it 'maps each IANA hostname to its own parser class' do
    expect(Whois::Parser.parser_klass('whois.publicinterestregistry.org'))
      .to eq(described_class)
    expect(Whois::Parser.parser_klass('whois.punktum.dk'))
      .to eq(Whois::Parsers::WhoisPunktumDk)
  end

  it 'classifies the current .org registered and absent response formats' do
    registered = parse(described_class, org_registered, 'whois.publicinterestregistry.org')
    available = parse(described_class, org_available, 'whois.publicinterestregistry.org')

    expect(registered.domain).to eq('sample.org')
    expect(registered.status).to eq(:registered)
    expect(registered.registered?).to eq(true)
    expect(registered.available?).to eq(false)
    expect(available.status).to eq(:available)
    expect(available.available?).to eq(true)
    expect(available.registered?).to eq(false)
  end

  it 'classifies the current .dk registered and absent response formats' do
    registered = parse(Whois::Parsers::WhoisPunktumDk, dk_registered, 'whois.punktum.dk')
    available = parse(Whois::Parsers::WhoisPunktumDk, dk_available, 'whois.punktum.dk')

    expect(registered.domain).to eq('sample.dk')
    expect(registered.status).to eq(:registered)
    expect(registered.registered?).to eq(true)
    expect(registered.available?).to eq(false)
    expect(available.status).to eq(:available)
    expect(available.available?).to eq(true)
    expect(available.registered?).to eq(false)
  end

  it 'keeps contradictory and partial .org responses unknown' do
    [
      "#{org_available}#{org_registered}",
      "#{org_available}Domain Name: sample.org\n",
      "#{org_available}Domain not found.\n",
      "Domain Name: sample.org\nRegistry Domain ID: REDACTED\n",
      "Domain Name: sample.org\nDomain Status: clientTransferProhibited\n",
    ].each do |body|
      parser = parse(described_class, body, 'whois.publicinterestregistry.org')
      expect(parser.status).to eq(:unknown)
      expect(parser.registered?).to eq(false)
      expect(parser.available?).to eq(false)
    end
  end

  it 'keeps contradictory and partial .dk responses unknown' do
    [
      "#{dk_available}#{dk_registered}",
      "#{dk_available}Domain: sample.dk\n",
      "#{dk_available}No entries found for the selected source.\n",
      "Domain: sample.dk\nRegistered: 2025-01-01\nStatus: Active\n",
      "Domain: sample.dk\nStatus: Active\n",
      "Domain: sample.dk\nRegistered: 2025-01-01\nStatus: Active\nStatus: Reserved\n",
    ].each do |body|
      parser = parse(Whois::Parsers::WhoisPunktumDk, body, 'whois.punktum.dk')
      expect(parser.status).to eq(:unknown)
      expect(parser.registered?).to eq(false)
      expect(parser.available?).to eq(false)
    end
  end

  it 'accepts CRLF lines for both current hosts' do
    org = parse(
      described_class,
      org_registered.gsub("\n", "\r\n"),
      'whois.publicinterestregistry.org'
    )
    dk = parse(
      Whois::Parsers::WhoisPunktumDk,
      dk_registered.gsub("\n", "\r\n"),
      'whois.punktum.dk'
    )

    expect(org.status).to eq(:registered)
    expect(dk.status).to eq(:registered)
    expect(parse(described_class, "Domain not found.\r\n", 'whois.publicinterestregistry.org').status).to eq(:available)
    expect(parse(Whois::Parsers::WhoisPunktumDk, "No entries found for the selected source.\r\n", 'whois.punktum.dk').status).to eq(:available)
  end

  it 'surfaces denial and throttling even when a record is present' do
    [
      [described_class, org_registered, 'whois.publicinterestregistry.org'],
      [Whois::Parsers::WhoisPunktumDk, dk_registered, 'whois.punktum.dk'],
    ].each do |klass, body, host|
      expect { parse(klass, "#{body}\nAccess denied\n", host).status }
        .to raise_error(Whois::ResponseIsUnavailable)
      expect { parse(klass, "#{body}\nToo many requests\n", host).status }
        .to raise_error(Whois::ResponseIsThrottled)
    end
  end

  it 'keeps mixed authoritative absence and denial unavailable' do
    [
      [described_class, org_available, 'whois.publicinterestregistry.org'],
      [Whois::Parsers::WhoisPunktumDk, dk_available, 'whois.punktum.dk'],
    ].each do |klass, body, host|
      expect { parse(klass, "#{body}Access denied\n", host).status }
        .to raise_error(Whois::ResponseIsUnavailable)
    end
  end

  it 'keeps the legacy PIR throttle marker unavailable on the current host' do
    body = fixture_body('whois.pir.org/org/response_throttled.txt')
    parser = parse(described_class, body, 'whois.publicinterestregistry.org')

    expect(parser.response_throttled?).to eq(true)
    expect { parser.status }.to raise_error(Whois::ResponseIsThrottled)
  end
end
