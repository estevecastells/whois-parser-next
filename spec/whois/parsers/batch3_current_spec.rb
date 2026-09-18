require 'spec_helper'

require 'whois/parsers/whois.dotgov.gov'
require 'whois/parsers/whois.mx'
require 'whois/parsers/whois.id'
require 'whois/parsers/whois.nic.online'
require 'whois/parsers/whois.nic.ar'
require 'whois/parsers/whois.sk-nic.sk'
require 'whois/parsers/whois.sgnic.sg'
require 'whois/parsers/whois.hkirc.hk'
require 'whois/parsers/whois.ua'
require 'whois/parsers/whois.dns.pt'
require 'whois/parsers/whois.gg'
require 'whois/parsers/whois.nic.im'
require 'whois/parsers/whois.nic.la'

RSpec.describe 'current port-43 responses in the top-usage TLD batch' do
  def parser(klass, path)
    body = File.read(fixture('responses', path))
    klass.new(Whois::Record::Part.new(body: body))
  end

  it 'parses current .gov availability without confusing a registered record' do
    expect(parser(Whois::Parsers::WhoisDotgovGov,
                  'whois.dotgov.gov/gov/current_registered.txt').status).to eq(:registered)
    expect(parser(Whois::Parsers::WhoisDotgovGov,
                  'whois.dotgov.gov/gov/current_available.txt').status).to eq(:available)
  end

  it 'keeps the current .mx hostname covered by the existing parser' do
    expect(Whois::Parser.parser_klass('whois.mx')).to eq(Whois::Parsers::WhoisMx)
  end

  it 'parses current .id records and absence' do
    registered = parser(Whois::Parsers::WhoisId, 'whois.id/id/current_registered.txt')
    available = parser(Whois::Parsers::WhoisId, 'whois.id/id/current_available.txt')

    expect(registered.status).to eq(:registered)
    expect(registered.created_on).to eq(Time.parse('2004-12-18T13:33:21Z'))
    expect(registered.expires_on).to eq(Time.parse('2027-09-01T23:59:59Z'))
    expect(registered.nameservers.map(&:name)).to eq(%w[ns1.google.com ns2.google.com])
    expect(available.status).to eq(:available)
  end

  it 'parses current .online records and availability' do
    registered = parser(Whois::Parsers::WhoisNicOnline,
                        'whois.nic.online/online/current_registered.txt')
    available = parser(Whois::Parsers::WhoisNicOnline,
                       'whois.nic.online/online/current_available.txt')

    expect(registered.status).to eq(:registered)
    expect(registered.expires_on).to eq(Time.parse('2027-08-19T23:59:59Z'))
    expect(registered.nameservers.map(&:name)).to eq(%w[ns1.googledomains.com ns2.googledomains.com])
    expect(available.status).to eq(:available)
  end

  it 'parses NIC Argentina registered and available responses' do
    registered = parser(Whois::Parsers::WhoisNicAr,
                        'whois.nic.ar/ar/current_registered.txt')
    available = parser(Whois::Parsers::WhoisNicAr,
                       'whois.nic.ar/ar/current_available.txt')

    expect(registered.domain).to eq('google.com.ar')
    expect(registered.status).to eq(:registered)
    expect(registered.expires_on).to eq(Time.parse('2027-07-08 00:00:00'))
    expect(available.status).to eq(:available)
    expect(available.registered?).to eq(false)
  end

  it 'parses current .sk status and nameservers' do
    registered = parser(Whois::Parsers::WhoisSkNicSk,
                        'whois.sk-nic.sk/sk/current_registered.txt')
    available = parser(Whois::Parsers::WhoisSkNicSk,
                       'whois.sk-nic.sk/sk/current_available.txt')

    expect(registered.status).to eq(:registered)
    expect(registered.nameservers.map(&:name)).to eq(%w[ns1.google.com ns2.google.com])
    expect(available.status).to eq(:available)
  end

  it 'parses current SGNIC status and nameservers' do
    registered = parser(Whois::Parsers::WhoisSgnicSg,
                        'whois.sgnic.sg/sg/current_registered.txt')
    available = parser(Whois::Parsers::WhoisSgnicSg,
                       'whois.sgnic.sg/sg/current_available.txt')

    expect(registered.registered?).to eq(true)
    expect(registered.nameservers.map(&:name)).to eq(%w[ns1.google.com ns2.google.com])
    expect(available.available?).to eq(true)
  end

  it 'recognizes the current HKIRC not-found code' do
    expect(parser(Whois::Parsers::WhoisHkircHk,
                  'whois.hkirc.hk/hk/current_available.txt').status).to eq(:available)
  end

  it 'accepts current UAEPP EPP status values' do
    registered = parser(Whois::Parsers::WhoisUa, 'whois.ua/ua/current_registered.txt')

    expect(registered.status).to eq(:registered)
    expect(registered.registered?).to eq(true)
  end

  it 'parses current .pt labels, dates, and nameservers' do
    registered = parser(Whois::Parsers::WhoisDnsPt,
                        'whois.dns.pt/pt/current_registered.txt')
    available = parser(Whois::Parsers::WhoisDnsPt,
                       'whois.dns.pt/pt/current_available.txt')

    expect(registered.status).to eq(:registered)
    expect(registered.created_on).to eq(Time.utc(2003, 1, 9))
    expect(registered.expires_on).to eq(Time.utc(2027, 2, 28, 23, 59))
    expect(registered.nameservers.map(&:name)).to eq(%w[ns3.google.com ns4.google.com])
    expect(available.status).to eq(:available)
  end

  it 'parses the current CIDR .gg format' do
    registered = parser(Whois::Parsers::WhoisGg,
                        'whois.gg/gg/current_registered.txt')
    available = parser(Whois::Parsers::WhoisGg,
                       'whois.gg/gg/current_available.txt')

    expect(registered.domain).to eq('google.gg')
    expect(registered.status).to eq(:registered)
    expect(registered.created_on).to eq(Time.parse('30 April 2003'))
    expect(registered.nameservers.map(&:name)).to eq(%w[ns1.google.com ns2.google.com])
    expect(available.status).to eq(:available)
  end

  it 'parses .im nameservers without a space after the field separator' do
    registered = parser(Whois::Parsers::WhoisNicIm,
                        'whois.nic.im/im/current_registered.txt')

    expect(registered.nameservers.map(&:name)).to eq(%w[ns1.google.com ns2.google.com])
  end

  it 'recognizes the current CentralNic .la not-found response' do
    expect(parser(Whois::Parsers::WhoisNicLa,
                  'whois.nic.la/la/current_available.txt').available?).to eq(true)
  end
end
