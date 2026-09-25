require 'spec_helper'
require 'whois/parsers/whois.registre.ma'

RSpec.describe Whois::Parsers::WhoisRegistreMa, 'current .ma WHOIS evidence' do
  let(:host) { 'whois.registre.ma' }

  def parser_for(response)
    body = File.read(fixture('responses', 'audit_20260925_rank131_ma', host, "#{response}.txt"))
    described_class.new(Whois::Record::Part.new(body: body, host: host))
  end

  it 'uses the IANA-listed standard WHOIS host' do
    server = Whois::Server.find_for_domain('google.ma')

    expect(server.host).to eq(host)
    expect(server).to be_a(Whois::Server::Adapters::Standard)
    expect(Whois::Parser.parser_klass(host)).to eq(described_class)
  end

  it 'classifies the observed EPP record and exact no-object response' do
    registered = parser_for('registered')
    absent = parser_for('available')

    expect(registered.status).to eq(:registered)
    expect(registered.registered?).to eq(true)
    expect(registered.available?).to eq(false)

    expect(absent.status).to eq(:available)
    expect(absent.registered?).to eq(false)
    expect(absent.available?).to eq(true)
  end

  it 'does not treat domain-name-only or unobserved status text as registration' do
    [parser_for('domain_name_only'), parser_for('unknown_status')].each do |parser|
      expect(parser.status).to eq(:unknown)
      expect(parser.registered?).to eq(false)
      expect(parser.available?).to eq(false)
    end

    wrong_suffix = described_class.new(
      Whois::Record::Part.new(
        body: "Domain Name: example.invalid\nThe queried object does not exist: No Object Found\n",
        host: host
      )
    )
    expect(wrong_suffix.status).to eq(:unknown)
    expect(wrong_suffix.registered?).to eq(false)
    expect(wrong_suffix.available?).to eq(false)
  end

  it 'keeps conflicting absence and registered evidence unknown' do
    parser = parser_for('ambiguous')

    expect(parser.status).to eq(:unknown)
    expect(parser.registered?).to eq(false)
    expect(parser.available?).to eq(false)
  end

  it 'raises on empty, denied, and rate-limited replies despite record-looking lines' do
    empty = described_class.new(Whois::Record::Part.new(body: '', host: host))
    denied = parser_for('denied')
    throttled = parser_for('rate_limited')

    [empty, denied].each do |parser|
      expect { parser.status }.to raise_error(Whois::ResponseIsUnavailable)
      expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable)
      expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable)
    end

    expect { throttled.status }.to raise_error(Whois::ResponseIsThrottled)
    expect { throttled.registered? }.to raise_error(Whois::ResponseIsThrottled)
    expect { throttled.available? }.to raise_error(Whois::ResponseIsThrottled)
  end

  it 'retains the earlier exact rwhois registered and no-object forms' do
    registered = described_class.new(
      Whois::Record::Part.new(
        body: File.read(fixture('responses', host, 'ma', 'status_registered.txt')),
        host: host
      )
    )
    absent = described_class.new(
      Whois::Record::Part.new(
        body: File.read(fixture('responses', host, 'ma', 'status_available.txt')),
        host: host
      )
    )

    expect(registered.status).to eq(:registered)
    expect(absent.status).to eq(:available)
  end
end
