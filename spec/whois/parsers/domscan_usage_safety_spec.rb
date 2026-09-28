require 'spec_helper'
require 'whois/parsers/whois.eu'
require 'whois/parsers/whois.nic.cl'

RSpec.describe Whois::Parsers::WhoisEu, 'DomScan-observed EU and Chile WHOIS classification' do
  def parse(klass, body)
    klass.new(Whois::Record::Part.new(body: body))
  end

  it 'classifies current EU registered and available replies' do
    registered = parse(described_class, File.read(fixture('responses', 'whois.eu/eu/status_registered.txt')))
    available = parse(described_class, File.read(fixture('responses', 'whois.eu/eu/status_available.txt')))

    expect(registered.status).to eq(:registered)
    expect(registered.registered?).to eq(true)
    expect(available.status).to eq(:available)
    expect(available.available?).to eq(true)
  end

  it 'keeps EU disclaimers, denial notices, and contradictory replies unknown' do
    disclaimer = File.read(fixture('responses', 'whois.eu/eu/status_registered.txt')).split('% WHOIS google.eu').first
    registered_body = File.read(fixture('responses', 'whois.eu/eu/status_registered.txt'))
    [
      disclaimer,
      'Access to the WHOIS service is denied',
      "Domain: example.eu\nStatus: AVAILABLE\nRegistrar:\n",
      "Domain: example.eu\nRegistrar:\n",
      "Domain: example.eu\nName servers:\n",
      "Domain: example.eu\nStatus: RESERVED\nRegistrar:\n  Name: Registry\n",
      "Domain: example.eu\nStatus: AVAILABLE\nRegistrar:\n  Name: Registry\n",
      "Domain: example.eu\nStatus: AVAILABLE\nStatus: RESERVED\n",
      "Domain: example.eu\nStatus: AVAILABLE\nStatus: AVAILABLE\n",
      "Domain: example.eu\nStatus: AVAILABLE\nAccess denied\n",
      "Domain: example.eu\nStatus: AVAILABLE\nToo many requests\n",
      "#{registered_body}Access denied\n",
      registered_body.sub('Domain: google.eu', "Domain: google.eu\nDomain: other.eu"),
      registered_body.sub('% WHOIS google.eu', '% WHOIS other.eu'),
    ].each do |body|
      parser = parse(described_class, body)
      expect(parser.status).to eq(:unknown)
      expect(parser.registered?).to eq(false)
      expect(parser.available?).to eq(false)
    end
  end

  it 'does not expose a registered classification when EURid throttles the reply' do
    body = "#{File.read(fixture('responses', 'whois.eu/eu/status_registered.txt'))}Still in grace period, wait 60 seconds\n"
    parser = parse(described_class, body)

    expect { parser.status }.to raise_error(Whois::ResponseIsThrottled)
  end

  it 'classifies current Chilean registered and absence replies' do
    registered = parse(Whois::Parsers::WhoisNicCl, File.read(fixture('responses', 'whois.nic.cl/cl/current_status_registered_redacted.txt')))
    available = parse(Whois::Parsers::WhoisNicCl, File.read(fixture('responses', 'whois.nic.cl/cl/current_status_available.txt')))

    expect(registered.status).to eq(:registered)
    expect(registered.registered?).to eq(true)
    expect(available.status).to eq(:available)
    expect(available.available?).to eq(true)
  end

  it 'keeps Chilean blocks, partial records, and contradictions unknown' do
    registered_body = File.read(fixture('responses', 'whois.nic.cl/cl/current_status_registered_redacted.txt'))
    [
      'Your IP is not authorised to query this service.',
      'Registrar name: NIC Chile',
      "example.cl: no entries found.\nRegistrar name: NIC Chile\nCreation date: 2020-03-03 15:00:00 CLST\n",
      "example.cl: no entries found.\nRegistrant organization: Example Corp\n",
      "example.cl: no entries found.\n#{registered_body}",
      "Your IP is not authorised to query this service.\n#{registered_body}",
      registered_body.sub('Creation date: 2020-03-03', 'Creation date: 2020-99-99'),
      "Registrar name: NIC Chile\nCreation date: 2020-03-03 15:00:00 CLST\n",
    ].each do |body|
      parser = parse(Whois::Parsers::WhoisNicCl, body)
      expect(parser.status).to eq(:unknown)
      expect(parser.registered?).to eq(false)
      expect(parser.available?).to eq(false)
    end
  end

  it 'accepts CRLF-delimited registered records from both registries' do
    eu_body = File.read(fixture('responses', 'whois.eu/eu/status_registered.txt')).gsub("\n", "\r\n")
    cl_body = File.read(fixture('responses', 'whois.nic.cl/cl/current_status_registered_redacted.txt')).gsub("\n", "\r\n")

    expect(parse(described_class, eu_body).status).to eq(:registered)
    expect(parse(Whois::Parsers::WhoisNicCl, cl_body).status).to eq(:registered)
  end
end
