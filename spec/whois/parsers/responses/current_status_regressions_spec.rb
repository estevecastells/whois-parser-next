require 'spec_helper'

require 'whois/parsers/whois.srs.net.nz.rb'
require 'whois/parsers/whois.nic.link.rb'
require 'whois/parsers/whois.nic.cl.rb'
require 'whois/parsers/whois.thnic.co.th.rb'
require 'whois/parsers/whois.aeda.net.ae.rb'
require 'whois/parsers/whois.mynic.my.rb'
require 'whois/parsers/whois.register.si.rb'
require 'whois/parsers/whois.website.ws.rb'
require 'whois/parsers/whois.register.bg.rb'
require 'whois/parsers/whois.nic.kz.rb'
require 'whois/parsers/whois.rnids.rs.rb'
require 'whois/parsers/whois.nic.so.rb'
require 'whois/parsers/kero.yachay.pe.rb'
require 'whois/parsers/whois.domainregistry.ie.rb'
require 'whois/parsers/whois.nic.es.rb'
require 'whois/parsers/whois.cira.ca.rb'

RSpec.describe Whois::Parser, 'current WHOIS status responses' do
  def parser(klass, path)
    body = File.read(fixture('responses', path))
    klass.new(Whois::Record::Part.new(body: body))
  end

  it 'parses current New Zealand responses' do
    registered = parser(Whois::Parsers::WhoisSrsNetNz, 'whois.srs.net.nz/nz/current_status_registered.txt')
    available = parser(Whois::Parsers::WhoisSrsNetNz, 'whois.srs.net.nz/nz/current_status_available.txt')

    expect(registered.status).to eq(:registered)
    expect(registered.domain).to eq('google.co.nz')
    expect(registered.nameservers.map(&:name)).to eq(%w[ns1.google.com ns2.google.com])
    expect(available.status).to eq(:available)
  end

  it 'does not treat empty .es name-server rows as IPv4 labels' do
    registered = parser(Whois::Parsers::WhoisNicEs, 'whois.nic.es/es/status_registered.txt')

    expect(registered.nameservers.map(&:name)).to eq(%w[ns2.google.com ns1.google.com])
  end

  it 'does not report an invalid CIRA status as registered' do
    invalid = parser(Whois::Parsers::WhoisCiraCa, 'whois.cira.ca/ca/status_invalid.txt')

    expect(invalid.status).to eq(:invalid)
    expect(invalid.registered?).to eq(false)
  end

  it 'parses current .link responses' do
    registered = parser(Whois::Parsers::WhoisNicLink, 'whois.nic.link/link/current_status_registered.txt')
    available = parser(Whois::Parsers::WhoisNicLink, 'whois.nic.link/link/current_status_available.txt')

    expect(registered.status).to eq(:registered)
    expect(registered.domain).to eq('google.link')
    expect(available.status).to eq(:available)
  end

  it 'parses current Chile availability and nameserver lines' do
    response = parser(Whois::Parsers::WhoisNicCl, 'whois.nic.cl/cl/current_status_available.txt')

    expect(response.available?).to eq(true)
    expect(response.status).to eq(:available)
  end

  it 'parses current Thailand status wording' do
    registered = parser(Whois::Parsers::WhoisThnicCoTh, 'whois.thnic.co.th/th/current_status_registered.txt')
    available = parser(Whois::Parsers::WhoisThnicCoTh, 'whois.thnic.co.th/th/current_status_available.txt')

    expect(registered.status).to eq(:registered)
    expect(available.status).to eq(:available)
  end

  it 'parses current United Arab Emirates responses' do
    registered = parser(Whois::Parsers::WhoisAedaNetAe, 'whois.aeda.net.ae/ae/current_status_registered.txt')
    available = parser(Whois::Parsers::WhoisAedaNetAe, 'whois.aeda.net.ae/ae/current_status_available.txt')

    expect(registered.status).to eq(:registered)
    expect(available.status).to eq(:available)
  end

  it 'parses the current Malaysian availability response' do
    response = parser(Whois::Parsers::WhoisMynicMy, 'whois.mynic.my/my/current_status_available.txt')

    expect(response.available?).to eq(true)
    expect(response.status).to eq(:available)
  end

  it 'parses current Slovenia, Samoa, and Bulgaria statuses' do
    si = parser(Whois::Parsers::WhoisRegisterSi, 'whois.register.si/si/current_status_registered.txt')
    ws = parser(Whois::Parsers::WhoisWebsiteWs, 'whois.website.ws/ws/current_status_available.txt')
    bg_registered = parser(Whois::Parsers::WhoisRegisterBg, 'whois.register.bg/bg/current_status_registered.txt')
    bg_available = parser(Whois::Parsers::WhoisRegisterBg, 'whois.register.bg/bg/current_status_available.txt')

    expect(si.status).to eq(:registered)
    expect(ws.status).to eq(:available)
    expect(bg_registered.status).to eq(:registered)
    expect(bg_available.status).to eq(:available)
  end

  it 'parses the current Kazakhstan response layout' do
    registered = parser(Whois::Parsers::WhoisNicKz, 'whois.nic.kz/kz/current_status_registered.txt')
    available = parser(Whois::Parsers::WhoisNicKz, 'whois.nic.kz/kz/current_status_available.txt')

    expect(registered.status).to eq(['ok'])
    expect(registered.created_on).to be_a(Time)
    expect(registered.updated_on).to be_a(Time)
    expect(registered.nameservers.map(&:name)).to eq(%w[ns1.google.com ns2.google.com])
    expect(available.available?).to eq(true)
  end

  it 'parses current Serbia, Somalia, Peru, and Ireland responses' do
    rs = parser(Whois::Parsers::WhoisRnidsRs, 'whois.rnids.rs/rs/current_status_registered.txt')
    so = parser(Whois::Parsers::WhoisNicSo, 'whois.nic.so/so/current_status_available.txt')
    pe_registered = parser(Whois::Parsers::KeroYachayPe, 'kero.yachay.pe/pe/current_status_registered.txt')
    pe_available = parser(Whois::Parsers::KeroYachayPe, 'kero.yachay.pe/pe/current_status_available.txt')
    ie_registered = parser(
      Whois::Parsers::WhoisDomainregistryIe,
      'whois.domainregistry.ie/ie/current_status_registered.txt'
    )
    ie_available = parser(
      Whois::Parsers::WhoisDomainregistryIe,
      'whois.domainregistry.ie/ie/current_status_available.txt'
    )

    expect(rs.status).to eq(:registered)
    expect(so.available?).to eq(true)
    expect(pe_registered.status).to eq(:registered)
    expect(pe_available.status).to eq(:available)
    expect(ie_registered.status).to eq(:registered)
    expect(ie_available.status).to eq(:available)
  end
end
