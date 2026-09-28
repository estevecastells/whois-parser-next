require 'spec_helper'

require 'whois/parsers/whois.nic.store'
require 'whois/parsers/whois.nic.sbs'
require 'whois/parsers/whois.nic.quest'
require 'whois/parsers/whois.nic.online'
require 'whois/parsers/whois.nic.one'
require 'whois/parsers/whois.pknic.net.pk'

RSpec.describe Whois::Parser, 'DomScan N-S WHOIS suffix truth cases' do
  let(:cases) do
    {
    'store' => {
      host: 'whois.nic.store', klass: Whois::Parsers::WhoisNicStore,
      registered: 'topdomains_201_225/whois.nic.store/registered.txt',
      available: 'topdomains_201_225/whois.nic.store/available.txt',
      conflict: '>>> Domain google.store is available for registration',
    },
    'sbs' => {
      host: 'whois.nic.sbs', klass: Whois::Parsers::WhoisNicSbs,
      registered: 'whois.nic.sbs/sbs/status_registered_redacted.txt',
      available: 'whois.nic.sbs/sbs/status_available.txt',
      conflict: 'The queried object does not exist: DOMAIN NOT FOUND',
    },
    'quest' => {
      host: 'whois.nic.quest', klass: Whois::Parsers::WhoisNicQuest,
      registered: 'whois.nic.quest/quest/status_registered_redacted.txt',
      available: 'whois.nic.quest/quest/status_available.txt',
      conflict: 'The queried object does not exist: DOMAIN NOT FOUND',
    },
    'online' => {
      host: 'whois.nic.online', klass: Whois::Parsers::WhoisNicOnline,
      registered: 'whois.nic.online/online/current_registered.txt',
      available: 'whois.nic.online/online/current_available.txt',
      conflict: '>>> Domain google.online is available for registration',
    },
    'one' => {
      host: 'whois.nic.one', klass: Whois::Parsers::WhoisNicOne,
      registered: 'audit_20260919_ranks101_125/whois.nic.one/one/status_registered.txt',
      available: 'audit_20260919_ranks101_125/whois.nic.one/one/status_available.txt',
      conflict: 'No Data Found',
    },
    'pk' => {
      host: 'whois.pknic.net.pk', klass: Whois::Parsers::WhoisPknicNetPk,
      registered: 'whois.pknic.net.pk/registered.txt',
      available: 'whois.pknic.net.pk/available.txt',
      conflict_fixture: 'whois.pknic.net.pk/ambiguous.txt',
    },
    }.freeze
  end

  def parser_for(host, klass, body)
    Whois::Parser.parser_for(Whois::Record::Part.new(body: body, host: host)).tap do |parser|
      expect(parser).to be_a(klass)
    end
  end

  def fixture_body(path)
    File.read(fixture('responses', path))
  end

  it 'uses the IANA-listed WHOIS host for the five standard WHOIS routes and the observed PKNIC parser for .pk' do
    standard_hosts = %w[store sbs quest online one]
    standard_hosts.each do |tld|
      server = Whois::Server.find_for_domain("example.#{tld}")
      expect(server&.host).to eq(cases.fetch(tld).fetch(:host)), tld
    end

    # Ruby Whois deliberately uses its web adapter for .pk, while DomScan's
    # observed port-43 host remains covered by the suffix-specific parser.
    expect(Whois::Server.find_for_domain('example.pk')).to be_a(Whois::Server::Adapters::Web)
    cases.each_value do |item|
      parser_for(item.fetch(:host), item.fetch(:klass), '')
    end
  end

  it 'parses each suffix-specific registered and authoritative absence response' do
    cases.each do |tld, item|
      registered = parser_for(item.fetch(:host), item.fetch(:klass), fixture_body(item.fetch(:registered)))
      expect(registered.registered?).to eq(true), tld
      expect(registered.available?).to eq(false), tld

      available = parser_for(item.fetch(:host), item.fetch(:klass), fixture_body(item.fetch(:available)))
      expect(available.available?).to eq(true), tld
      expect(available.registered?).to eq(false), tld
    end
  end

  it 'keeps unrecognised and conflicting registration/absence responses unknown' do
    cases.each do |tld, item|
      unknown_body =
        if tld == 'pk'
          "Domain: example.pk\nStatus: Pending\n"
        elsif tld == 'one'
          "Domain Name: example.one\n"
        else
          "Domain Name: example.#{tld}\nDomain Status: unknown\n"
        end
      unknown = parser_for(item.fetch(:host), item.fetch(:klass), unknown_body)
      expect(unknown.available?).to eq(false), tld
      expect(unknown.registered?).to eq(false), tld

      body =
        if item[:conflict_fixture]
          fixture_body(item.fetch(:conflict_fixture))
        elsif tld == 'one'
          "#{item.fetch(:conflict)}\n#{fixture_body(item.fetch(:registered))}"
        else
          "#{fixture_body(item.fetch(:registered))}\n#{item.fetch(:conflict)}\n"
        end
      ambiguous = parser_for(item.fetch(:host), item.fetch(:klass), body)
      expect(ambiguous.available?).to eq(false), tld
      expect(ambiguous.registered?).to eq(false), tld
      expect(ambiguous.status).to eq(:unknown) unless tld == 'quest'
    end
  end

  it 'does not let a denial appended to authoritative absence become available' do
    cases.each do |tld, item|
      body = "#{fixture_body(item.fetch(:available))}\nAccess denied\n"
      parser = parser_for(item.fetch(:host), item.fetch(:klass), body)

      expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable), tld
      expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable), tld
    end
  end

  it 'does not let a throttle appended to authoritative absence become available' do
    cases.each do |tld, item|
      body = "#{fixture_body(item.fetch(:available))}\nToo many requests\n"
      parser = parser_for(item.fetch(:host), item.fetch(:klass), body)

      expect { parser.available? }.to raise_error(Whois::ResponseIsThrottled), tld
      expect { parser.registered? }.to raise_error(Whois::ResponseIsThrottled), tld
    end
  end
end
