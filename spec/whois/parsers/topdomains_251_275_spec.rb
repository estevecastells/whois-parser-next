require 'spec_helper'

require 'whois/parsers/whois.nic.nf'
require 'whois/parsers/whois.nic.ink'
require 'whois/parsers/whois.sr'
require 'whois/parsers/whois.nic.delivery'
require 'whois/parsers/whois.nic.direct'
require 'whois/parsers/whois.nic.games'
require 'whois/parsers/whois.nic.icu'
require 'whois/parsers/whois.nic.software'
require 'whois/parsers/whois.nic.solutions'
require 'whois/parsers/whois.nic.tools'
require 'whois/parsers/whois.nic.work'
require 'whois/parsers/whois.nic.dm'
require 'whois/parsers/whois.nic.fo'
require 'whois/parsers/whois.uniregistry.net'

RSpec.describe Whois::Parser, 'ICANN DNS Magnitude ranks 251-275 audit' do
  def parser(host, domain, fixture_name)
    body = File.read(fixture('responses', 'topdomains_251_275', host, fixture_name))
    server = Whois::Server.find_for_domain(domain)
    record = Whois::Record.new(
      server,
      [Whois::Record::Part.new(body: body, host: host)]
    )
    Whois::Parser.new(record)
  end

  def parser_for_body(host, body)
    record = Whois::Record.new(
      nil,
      [Whois::Record::Part.new(body: body, host: host)]
    )
    Whois::Parser.new(record)
  end

  it 'keeps the current standard-host mappings' do
    {
      'nf' => 'whois.nic.nf',
      'ink' => 'whois.nic.ink',
      'delivery' => 'whois.nic.delivery',
      'direct' => 'whois.nic.direct',
      'games' => 'whois.nic.games',
      'icu' => 'whois.nic.icu',
      'software' => 'whois.nic.software',
      'solutions' => 'whois.nic.solutions',
      'tools' => 'whois.nic.tools',
      'work' => 'whois.nic.work',
      'dm' => 'whois.nic.dm',
      'fo' => 'whois.nic.fo',
    }.each do |tld, host|
      server = Whois::Server.find_for_domain("google.#{tld}")

      expect(server.instance_variable_get(:@host)).to eq(host)
      expect(described_class.parser_klass(host)).to be < Whois::Parsers::Base
    end
  end

  it 'parses the current CoCCA .nf record and no-object response' do
    registered = parser('whois.nic.nf', 'google.nf', 'registered.txt')
    available = parser('whois.nic.nf', 'zz2510-20260919.nf', 'available.txt')

    expect(registered.status).to eq(:registered)
    expect(registered.nameservers.map(&:name)).to eq(%w[ns1.google.com ns2.google.com])
    expect(available.status).to eq(:available)
    expect(available.registered?).to eq(false)
  end

  it 'parses current .sr registration and exact no-object responses' do
    registered = parser('whois.sr', 'google.sr', 'registered.txt')
    available = parser('whois.sr', 'codex-rank251-20260925.sr', 'available.txt')

    expect(registered.domain).to eq('google.sr')
    expect(registered.status).to eq(:registered)
    expect(registered.nameservers.map(&:name)).to eq(%w[
      ns4.google.com ns3.google.com ns2.google.com ns1.google.com
    ])
    expect(available.status).to eq(:available)
    expect(available.registered?).to eq(false)
  end

  it 'keeps denied, throttled, and ambiguous .sr responses non-positive' do
    denied = parser_for_body('whois.sr', "Requests of this client are not permitted.\n")
    throttled = parser_for_body('whois.sr', "Query rate limit exceeded.\n")
    ambiguous = parser_for_body('whois.sr', "Domain: codex-rank251-20260925.sr\n")

    expect { denied.status }.to raise_error(Whois::ResponseIsUnavailable)
    expect { throttled.status }.to raise_error(Whois::ResponseIsThrottled)
    expect(ambiguous.status).to eq(:unknown)
    expect(ambiguous.available?).to eq(false)
    expect(ambiguous.registered?).to eq(false)
  end

  it 'parses the current Identity Digital .ink and .icu records' do
    ink_registered = parser('whois.nic.ink', 'google.ink', 'registered.txt')
    ink_available = parser('whois.nic.ink', 'zz2511-20260919.ink', 'available.txt')
    icu_registered = parser('whois.nic.icu', 'google.icu', 'registered.txt')
    icu_available = parser('whois.nic.icu', 'zz25112-20260919.icu', 'available.txt')

    expect(ink_registered.status).to eq(:registered)
    expect(ink_available.status).to eq(:available)
    expect(icu_registered.status).to eq(:registered)
    expect(icu_available.status).to eq(:available)
  end

  it 'keeps explicit unsupported Identity Digital responses unavailable' do
    %w[delivery direct games software solutions tools].each do |tld|
      host = "whois.nic.#{tld}"
      subject = parser(host, "zz251-20260919.#{tld}", 'unsupported.txt')

      expect { subject.status }.to raise_error(Whois::ResponseIsUnavailable)
    end
  end

  it 'does not infer registration from the .work reservation response' do
    subject = parser('whois.nic.work', 'google.work', 'reserved.txt')

    expect(subject.status).to eq(:unknown)
    expect(subject.registered?).to eq(false)
    expect(subject.available?).to eq(false)
  end

  it 'does not classify a restricted .dm name as available' do
    subject = parser('whois.nic.dm', 'zz2516-20260919.dm', 'restricted.txt')

    expect { subject.status }.to raise_error(Whois::ResponseIsUnavailable)
  end

  it 'parses a current .dm registered response after the registry footer' do
    subject = parser('whois.nic.dm', 'google.dm', 'registered.txt')

    expect(subject.status).to eq(:registered)
    expect(subject.nameservers.map(&:name)).to eq(%w[ns1.google.com ns2.google.com])
  end

  it 'parses current .gi evidence through the shared Afilias endpoint' do
    registered = parser('whois.afilias-grs.info', 'nic.gi', 'registered.txt')
    available = parser('whois.afilias-grs.info', 'registry.gi', 'available.txt')

    expect(registered.registered?).to eq(true)
    expect(registered.nameservers.map(&:name)).to eq([
      'ns-1215.awsdns-23.org', 'ns-398.awsdns-49.com',
    ])
    expect(available.available?).to eq(true)
  end

  it 'normalizes current .fo records while preserving the legacy parser contract' do
    registered = parser('whois.nic.fo', 'google.fo', 'registered.txt')
    available = parser('whois.nic.fo', 'zz25114-20260919.fo', 'available.txt')

    expect(registered.status).to eq(:registered)
    expect(registered.domain).to eq('google.fo')
    expect(registered.nameservers.map(&:name)).to eq(%w[ns1.markmonitor.com ns3.markmonitor.com])
    expect(available.status).to eq(:available)
  end

  it 'treats the Uniregistry unsupported notice as unavailable' do
    subject = parser('whois.uniregistry.net', 'zz25124-20260919.hosting', 'unsupported.txt')

    expect { subject.status }.to raise_error(Whois::ResponseIsUnavailable)
  end
end
