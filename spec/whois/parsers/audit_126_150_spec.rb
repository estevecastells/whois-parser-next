require 'spec_helper'
require 'whois/parsers/whois.nic.hn'
require 'whois/parsers/whois.ati.tn'
require 'whois/parsers/whois.nic.li'
require 'whois/parsers/whois.cctld.by'
require 'whois/parsers/whois.nic.host'
require 'whois/parsers/whois.nic.cr'
require 'whois/parsers/whois.nic.ve'
require 'whois/parsers/whois.dns.lu'
require 'whois/parsers/whois.nic.ec'
require 'whois/parsers/whois.nic.ir'
require 'whois/parsers/whois.iis.nu'

AUDIT_126_150_FIXTURE_ROOT = 'responses/audit-126-150-2026-09-19'.freeze

RSpec.describe Whois::Parser, 'DNS Magnitude ranks 126-150 parser audit' do

  def parser_for(klass, path)
    body = File.read(fixture(AUDIT_126_150_FIXTURE_ROOT, path))
    klass.new(Whois::Record::Part.new(body: body))
  end

  it 'recognizes the current .hn no-object response as available' do
    parser = parser_for(Whois::Parsers::WhoisNicHn, 'whois.nic.hn/hn/status_available.txt')

    expect(parser.status).to eq(:available)
    expect(parser.available?).to eq(true)
    expect(parser.registered?).to eq(false)
  end

  it 'recognizes the current .tn no-object response as available' do
    parser = parser_for(Whois::Parsers::WhoisAtiTn, 'whois.ati.tn/tn/status_available.txt')

    expect(parser.status).to eq(:available)
    expect(parser.available?).to eq(true)
    expect(parser.registered?).to eq(false)
  end

  it 'recognizes the lower-case .by no-object response as available' do
    parser = parser_for(Whois::Parsers::WhoisCctldBy, 'whois.cctld.by/by/status_available.txt')

    expect(parser.status).to eq(:available)
    expect(parser.available?).to eq(true)
    expect(parser.registered?).to eq(false)
  end

  it 'does not classify the .li client denial as a registration' do
    parser = parser_for(Whois::Parsers::WhoisNicLi, 'whois.nic.li/li/response_denied.txt')

    expect(parser.response_unavailable?).to eq(true)
    expect { parser.status }.to raise_error(Whois::ResponseIsUnavailable)
    expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable)
    expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable)
  end

  it 'parses the current .host availability and registration responses' do
    available = parser_for(Whois::Parsers::WhoisNicHost, 'whois.nic.host/host/status_available.txt')
    registered = parser_for(Whois::Parsers::WhoisNicHost, 'whois.nic.host/host/status_registered.txt')

    expect(available.status).to eq(:available)
    expect(available.registered?).to eq(false)
    expect(registered.status).to eq(:registered)
    expect(registered.registered?).to eq(true)
    expect(registered.nameservers.map(&:name)).to eq(%w[ns1.googledomains.com ns2.googledomains.com])
  end

  it 'parses the current .cr availability and registration responses' do
    available = parser_for(Whois::Parsers::WhoisNicCr, 'whois.nic.cr/cr/status_available.txt')
    registered = parser_for(Whois::Parsers::WhoisNicCr, 'whois.nic.cr/cr/status_registered.txt')

    expect(available.status).to eq(:available)
    expect(available.registered?).to eq(false)
    expect(registered.status).to eq(:registered)
    expect(registered.domain).to eq('google.cr')
    expect(registered.nameservers.map(&:name)).to eq(%w[ns1.google.com ns2.google.com])
  end

  it 'parses the current .ve no-object and registered responses' do
    available = parser_for(Whois::Parsers::WhoisNicVe, 'whois.nic.ve/ve/status_available.txt')
    registered = parser_for(Whois::Parsers::WhoisNicVe, 'whois.nic.ve/ve/status_registered.txt')

    expect(available.status).to eq(:available)
    expect(available.registered?).to eq(false)
    expect(registered.status).to eq(:registered)
    expect(registered.registered?).to eq(true)
  end

  it 'keeps current healthy .lu, .ec, .ir, and .nu responses available' do
    {
      Whois::Parsers::WhoisDnsLu => 'whois.dns.lu/lu/status_available.txt',
      Whois::Parsers::WhoisNicEc => 'whois.nic.ec/ec/status_available.txt',
      Whois::Parsers::WhoisNicIr => 'whois.nic.ir/ir/status_available.txt',
      Whois::Parsers::WhoisIisNu => 'whois.iis.nu/nu/status_available.txt',
    }.each do |klass, path|
      parser = parser_for(klass, path)

      expect(parser.status).to eq(:available), klass.name
      expect(parser.available?).to eq(true), klass.name
      expect(parser.registered?).to eq(false), klass.name
    end
  end

  it 'loads the current .cr and .host port-43 server mappings' do
    expect(Whois::Server.find_for_domain('google.cr').host).to eq('whois.nic.cr')
    expect(described_class.parser_klass('whois.nic.cr').name).to eq('Whois::Parsers::WhoisNicCr')
    expect(Whois::Server.find_for_domain('google.host').host).to eq('whois.nic.host')
    expect(described_class.parser_klass('whois.nic.host').name).to eq('Whois::Parsers::WhoisNicHost')
  end
end
