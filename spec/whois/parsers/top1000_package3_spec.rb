require 'csv'
require 'spec_helper'

RSpec.describe Whois::Parser, 'ICANN DNS Magnitude package-3 WHOIS coverage' do
  let(:fixture_root) { File.expand_path('../../fixtures/responses/top1000_package3', __dir__) }

  def parser(host, fixture = nil, body: nil)
    body ||= File.read(File.join(fixture_root, fixture))
    Whois::Parser.parser_klass(host).new(Whois::Record::Part.new(body: body))
  end

  it 'loads every safe package-3 adapter instead of Blank' do
    hosts = %w[
      whois.nic.fox whois.nic.agency whois.nic.buzz whois.nic.cam whois.nic.codes
      whois.nic.casa whois.nic.academy whois.nic.love whois.nic.monster whois.nic.energy
      whois.nic.rest whois.nic.dog whois.nic.fan whois.nic.bar whois.nic.army whois.nic.xin
      whois.nic.capital whois.nic.berlin whois.nic.sap whois.nic.place whois.nic.nrw
      whois.nic.surf whois.nic.style whois.nic.rent whois.nic.photography whois.nic.estate
      whois.nic.university whois.nic.immo whois.nic.ceo whois.nic.football whois.nic.museum
      whois.nic.rodeo whois.nic.wedding whois.nic.bingo whois.nic.quebec whois.nic.schwarz
      whois.nic.basketball whois.nic.shoes whois.nic.glass whois.nic.insure whois.nic.hamburg
      whois.nic.graphics whois.nic.limo whois.nic.futbol whois.nic.jewelry whois.nic.aw
      whois.nic.boston whois.nic.broker whois.nic.mobile whois.nic.exposed whois.nic.feedback
      whois.nic.claims whois.nic.holiday whois-corsica.nic.fr whois.nic.yokohama
      whois.nic.cooking whois.nic.diamonds whois.nic.tennis whois.dotukr.com
      whois.teleinfo.cn whois.nic.talk whois.nic.fishing whois.nic.lease whois.nic.realty
      whois.nic.cricket whois.nic.vodka whois.nic.xn--mk1bu44c whois.nic.spot
      whois.nic.tires whois.nic.osaka whois.nic.condos whois.nic.kyoto whois.nic.toyota
      whois.nic.data whois.nic.man whois.nic.degree whois.nic.viajes
    ]

    safe_hosts = hosts - %w[
      whois.nic.google whois.nic.sky whois.nic.gdn whois.nic.med whois-corsica.nic.fr
      whois.nic.talk whois.nic.cricket whois.nic.vodka whois.nic.spot whois.nic.osaka
    ]

    safe_hosts.each do |host|
      expect(described_class.parser_klass(host).name).not_to eq('Whois::Parsers::Blank'), host
    end
  end

  it 'parses ICANN registered and authoritative absence markers' do
    expect(parser('whois.nic.buzz', 'base_icann_registered.txt').status).to eq(:registered)
    expect(parser('whois.nic.fox', 'available_no_data.txt').status).to eq(:available)
    expect(parser('whois.nic.cam', 'available_domain_not_found.txt').status).to eq(:available)
    expect(parser('whois.nic.love', 'available_radix.txt').status).to eq(:available)
    expect(parser('whois.nic.rodeo', 'reserved.txt').status).to eq(:reserved)
  end

  it 'reuses the explicit unsupported-registry family without claiming a result' do
    unsupported = %w[
      whois.nic.agency whois.nic.codes whois.nic.academy whois.nic.energy whois.nic.dog
      whois.nic.fan whois.nic.army whois.nic.capital whois.nic.place whois.nic.style
      whois.nic.photography whois.nic.estate whois.nic.university whois.nic.immo
      whois.nic.football whois.nic.bingo whois.nic.shoes whois.nic.glass whois.nic.insure
      whois.nic.graphics whois.nic.limo whois.nic.futbol whois.nic.jewelry whois.nic.broker
      whois.nic.exposed whois.nic.claims whois.nic.holiday whois.nic.diamonds
      whois.nic.tennis whois.nic.tires whois.nic.lease whois.nic.condos whois.nic.degree whois.nic.viajes
    ]

    unsupported.each do |host|
      expect { parser(host, 'unsupported.txt').status }.to raise_error(Whois::ResponseIsUnavailable), host
    end
  end

  it 'keeps empty, denied, and ambiguous ICANN responses out of registration' do
    expect { parser('whois.nic.buzz', body: '').status }.to raise_error(Whois::ResponseIsUnavailable)
    expect do
      parser('whois.nic.buzz', body: 'Access to the WHOIS service is denied.').registered?
    end.to raise_error(Whois::ResponseIsUnavailable)

    unknown = parser('whois.nic.buzz', body: 'Temporary registry response')
    expect(unknown.status).to eq(:unknown)
    expect(unknown.registered?).to eq(false)
    expect(unknown.available?).to eq(false)
  end

  it 'handles registries with distinct compact response contracts' do
    aw_registered = parser('whois.nic.aw', 'aw_registered.txt')
    expect(aw_registered.domain).to eq('google.aw')
    expect(aw_registered.status).to eq(:registered)
    expect(parser('whois.nic.aw', 'aw_available.txt').status).to eq(:available)

    expect(parser('whois.dotukr.com', 'dotukr_available.txt').status).to eq(:available)

    teleinfo = parser('whois.teleinfo.cn', 'teleinfo_registered.txt')
    expect(teleinfo.domain).to eq('google.xn--3ds443g')
    expect(teleinfo.status).to eq(:registered)
    expect(parser('whois.teleinfo.cn', 'teleinfo_available.txt').status).to eq(:available)

    expect(parser('whois.nic.xn--mk1bu44c', 'xn_available.txt').status).to eq(:available)
  end

  it 'reports retired WHOIS endpoints as unavailable rather than available' do
    %w[whois.nic.yokohama whois.nic.kyoto whois.nic.toyota].each do |host|
      retired = parser(host, 'retired.txt')
      expect { retired.status }.to raise_error(Whois::ResponseIsUnavailable)
      expect { retired.available? }.to raise_error(Whois::ResponseIsUnavailable)
      expect { retired.registered? }.to raise_error(Whois::ResponseIsUnavailable)
      expect(retired.response_unavailable?).to eq(true)
    end
  end
end
