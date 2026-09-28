require 'spec_helper'

require 'whois/parsers/whois.registry.gift'
require 'whois/parsers/whois.nixiregistry.in'
require 'whois/parsers/whois.weare.ie'
require 'whois/parsers/whois.nic.help'
require 'whois/parsers/whois.nic.homes'

GM_REGISTRY_MIGRATION_CASES = {
  'gift' => {
    host: 'whois.registry.gift', klass: Whois::Parsers::WhoisRegistryGift,
    domain: 'sample.gift',
  },
  'in' => {
    host: 'whois.nixiregistry.in', klass: Whois::Parsers::WhoisNixiregistryIn,
    domain: 'sample.in',
  },
  'ie' => {
    host: 'whois.weare.ie', klass: Whois::Parsers::WhoisWeareIe,
    domain: 'sample.ie', available_fixture: 'available_marker.txt',
  },
  'help' => {
    host: 'whois.nic.help', klass: Whois::Parsers::WhoisNicHelp,
    domain: 'sample.help',
  },
  'homes' => {
    host: 'whois.nic.homes', klass: Whois::Parsers::WhoisNicHomes,
    domain: 'sample.homes',
  },
}.freeze

# Restricted source payloads are omitted; these synthetic records preserve
# only the observed field shape needed to exercise parser behavior.
RSpec.describe Whois::Parser, 'G-M registry host migrations' do
  def parser(klass, host, body)
    klass.new(Whois::Record::Part.new(body: body, host: host))
  end

  def fixture_body(host, suffix, filename)
    File.read(fixture('responses', "#{host}/#{suffix}/#{filename}"))
  end

  GM_REGISTRY_MIGRATION_CASES.each do |suffix, details|
    it "parses a synthetic .#{suffix} record and the observed authoritative absence marker" do
      registered = parser(
        details.fetch(:klass),
        details.fetch(:host),
        fixture_body(details.fetch(:host), suffix, 'registered_synthetic.txt')
      )
      available = parser(
        details.fetch(:klass),
        details.fetch(:host),
        fixture_body(details.fetch(:host), suffix, details.fetch(:available_fixture, 'available.txt'))
      )

      expect(registered.status).to eq(:registered)
      expect(registered.domain.to_s.downcase).to eq(details.fetch(:domain))
      expect(registered.registered?).to eq(true)
      expect(registered.available?).to eq(false)
      expect(available.status).to eq(:available)
      expect(available.available?).to eq(true)
      expect(available.registered?).to eq(false)
    end

    it "keeps denied and ambiguous .#{suffix} replies non-positive" do
      klass = details.fetch(:klass)
      host = details.fetch(:host)
      ambiguous = parser(klass, host, "Domain Name: sample.#{suffix}\n")
      denied = parser(klass, host, "Access to the WHOIS service is denied.\n")
      mixed_body = <<~RESPONSE
        Domain Name: sample.#{suffix}
        Registrar: Example Registrar
        Creation Date: 2020-01-01
        Access to the WHOIS service is denied.
      RESPONSE
      mixed = parser(klass, host, mixed_body)

      expect(ambiguous.status).to eq(:unknown)
      expect(ambiguous.registered?).to eq(false)
      expect(ambiguous.available?).to eq(false)
      expect(denied.response_unavailable?).to eq(true)
      expect { denied.status }.to raise_error(Whois::ResponseIsUnavailable)
      expect(mixed.response_unavailable?).to eq(true)
      expect { mixed.status }.to raise_error(Whois::ResponseIsUnavailable)
    end
  end

  it 'loads a parser class for every current IANA-listed host' do
    GM_REGISTRY_MIGRATION_CASES.each_value do |details|
      expect(described_class.parser_klass(details.fetch(:host))).to eq(details.fetch(:klass))
    end
  end
end
