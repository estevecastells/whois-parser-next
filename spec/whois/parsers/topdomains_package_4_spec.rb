require 'spec_helper'

require 'whois/parsers/whois.nic.blog'
require 'whois/parsers/whois.kyregistry.ky'
require 'whois/parsers/whois.nic.barcelona'
require 'whois/parsers/whois.nic.bayern'
require 'whois/parsers/whois.nic.baby'
require 'whois/parsers/whois.nic.eus'
require 'whois/parsers/whois.nic.bzh'
require 'whois/parsers/whois.nic.fans'
require 'whois/parsers/whois.nic.gent'
require 'whois/parsers/whois.nic.quest'
require 'whois/parsers/whois.nic.ruhr'
require 'whois/parsers/whois.nic.ss'
require 'whois/parsers/whois.nic.tatar'
require 'whois/parsers/whois.nic.tirol'
require 'whois/parsers/whois.nic.wien'
require 'whois/parsers/whois.nic.uno'
require 'whois/parsers/whois.ngtld.cn'
require 'whois/parsers/whois.publicinterestregistry.net'
require 'whois/parsers/whois.nic.accountant'
require 'whois/parsers/whois.nic.bible'
require 'whois/parsers/whois.nic.charity'
require 'whois/parsers/whois.nic.film'
require 'whois/parsers/whois.nic.coop'
require 'whois/parsers/whois.nic.gd'
require 'whois/parsers/whois.nic.pm'
require 'whois/parsers/whois.nic.fr'
require 'whois/parsers/whois.ax'

RSpec.describe Whois::Parser, 'ICANN DNS Magnitude package-4 parser coverage' do
  def parser_for(klass, path, host = nil)
    body = File.read(fixture('responses', "topdomains_package_4/#{path}"))
    klass.new(Whois::Record::Part.new(body: body, host: host))
  end

  it 'uses explicit unavailable adapters for current unsupported responses' do
    hosts = %w[
      airforce associates camera cards cash cleaning coffee construction cool
      cruises democrat directory engineer express forex fyi gmbh gratis haus
      immobilien international kaufen land legal management memorial moda
      mortgage partners photos plumbing recipes rentals restaurant sarl shopping
      soccer surgery theater toys villas voyage
    ]

    hosts.each do |tld|
      host = "whois.nic.#{tld}"
      parser = described_class.parser_for(
        Whois::Record::Part.new(
          body: File.read(fixture('responses', 'topdomains_package_4/unsupported/tld_not_supported.txt')),
          host: host
        )
      )

      expect(parser).to be_a(Whois::Parsers::BaseUnsupportedRegistry), tld
      expect(parser.response_unavailable?).to eq(true), tld
      expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable), tld
      expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable), tld
    end
  end

  it 'keeps explicit reservation responses unavailable' do
    reserved_classes = {
      'accountant' => Whois::Parsers::WhoisNicAccountant,
      'bible' => Whois::Parsers::WhoisNicBible,
      'charity' => Whois::Parsers::WhoisNicCharity,
      'film' => Whois::Parsers::WhoisNicFilm,
      'ngo' => Whois::Parsers::WhoisPublicinterestregistryNet,
      'ong' => Whois::Parsers::WhoisPublicinterestregistryNet,
      'xn--55qx5d' => Whois::Parsers::WhoisNgtldCn,
      'xn--io0a7i' => Whois::Parsers::WhoisNgtldCn,
    }

    reserved_classes.each do |tld, klass|
      fixture_name =
        if %w[xn--55qx5d xn--io0a7i].include?(tld)
          'reserved/cnnic_reserved.txt'
        elsif %w[ngo ong].include?(tld)
          'reserved/reserved_policy.txt'
        else
          'reserved/reserved_domain.txt'
        end
      parser = parser_for(klass, fixture_name, "whois.nic.#{tld}")

      expect(parser.response_unavailable?).to eq(true), tld
      expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable), tld
      expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable), tld
    end
  end

  it 'parses CIRA-style .blog registration, absence, and restriction markers' do
    registered = parser_for(Whois::Parsers::WhoisNicBlog, 'cira/blog_registered.txt', 'whois.nic.blog')
    expect(registered.registered?).to eq(true)
    expect(registered.available?).to eq(false)

    available = parser_for(Whois::Parsers::WhoisNicBlog, 'cira/blog_available.txt', 'whois.nic.blog')
    expect(available.available?).to eq(true)
    expect(available.registered?).to eq(false)

    restricted = parser_for(Whois::Parsers::WhoisNicBlog, 'cira/blog_restricted.txt', 'whois.nic.blog')
    expect(restricted.response_unavailable?).to eq(true)
    expect { restricted.available? }.to raise_error(Whois::ResponseIsUnavailable)
    expect { restricted.registered? }.to raise_error(Whois::ResponseIsUnavailable)
  end

  it 'parses exact ICANN/Radix registered and available markers' do
    {
      Whois::Parsers::WhoisKyregistryKy => 'ky',
      Whois::Parsers::WhoisNicUno => 'uno',
    }.each do |klass, tld|
      registered = parser_for(klass, "#{tld == 'ky' ? 'icann' : 'uno'}/registered.txt", "whois.#{tld == 'ky' ? 'kyregistry.ky' : 'nic.uno'}")
      expect(registered.registered?).to eq(true), tld
      expect(registered.available?).to eq(false), tld

      available = parser_for(klass, "#{tld == 'ky' ? 'icann' : 'uno'}/available.txt", "whois.#{tld == 'ky' ? 'kyregistry.ky' : 'nic.uno'}")
      expect(available.available?).to eq(true), tld
      expect(available.registered?).to eq(false), tld
    end
  end

  it 'reuses the CentralNic no-object families' do
    {
      Whois::Parsers::WhoisNicBarcelona => 'no_matching_objects.txt',
      Whois::Parsers::WhoisNicBayern => 'no_matching_objects.txt',
      Whois::Parsers::WhoisNicEus => 'no_matching_objects.txt',
      Whois::Parsers::WhoisNicBaby => 'domain_not_found.txt',
      Whois::Parsers::WhoisNicFans => 'domain_not_found.txt',
      Whois::Parsers::WhoisNicGent => 'domain_not_found.txt',
      Whois::Parsers::WhoisNicQuest => 'domain_not_found.txt',
      Whois::Parsers::WhoisNicRuhr => 'domain_not_found.txt',
    }.each do |klass, absence_fixture|
      registered = parser_for(klass, 'centralnic/registered.txt')
      expect(registered.registered?).to eq(true), klass.name
      expect(registered.available?).to eq(false), klass.name

      available = parser_for(klass, "centralnic/#{absence_fixture}")
      expect(available.available?).to eq(true), klass.name
      expect(available.registered?).to eq(false), klass.name
    end
  end

  it 'parses the .bzh AFNIC absence marker with the ICANN record layout' do
    registered = parser_for(Whois::Parsers::WhoisNicBzh, 'bzh/registered.txt', 'whois.nic.bzh')
    expect(registered.registered?).to eq(true)
    expect(registered.available?).to eq(false)

    available = parser_for(Whois::Parsers::WhoisNicBzh, 'bzh/available.txt', 'whois.nic.bzh')
    expect(available.available?).to eq(true)
    expect(available.registered?).to eq(false)
  end

  it 'does not treat SSNIC prohibited strings as registration' do
    prohibited = parser_for(Whois::Parsers::WhoisNicSs, 'ss/registered_prohibited.txt', 'whois.nic.ss')
    expect(prohibited.status).to eq(:unknown)
    expect(prohibited.available?).to eq(false)
    expect(prohibited.registered?).to eq(false)

    available = parser_for(Whois::Parsers::WhoisNicSs, 'ss/available.txt', 'whois.nic.ss')
    expect(available.available?).to eq(true)
    expect(available.registered?).to eq(false)
  end

  it 'parses the Tatar object marker without accepting unknown responses' do
    registered = parser_for(Whois::Parsers::WhoisNicTatar, 'tatar/registered.txt', 'whois.nic.tatar')
    expect(registered.registered?).to eq(true)
    expect(registered.available?).to eq(false)

    available = parser_for(Whois::Parsers::WhoisNicTatar, 'tatar/available.txt', 'whois.nic.tatar')
    expect(available.available?).to eq(true)
    expect(available.registered?).to eq(false)

    unknown = parser_for(Whois::Parsers::WhoisNicTatar, 'tatar/available.txt', 'whois.nic.tatar')
    allow(unknown).to receive(:content_for_scanner).and_return("Temporary registry response\n")
    expect(unknown.status).to eq(:unknown)
    expect(unknown.registered?).to eq(false)
  end

  it 'parses reserved and available .tirol and .wien markers safely' do
    [Whois::Parsers::WhoisNicTirol, Whois::Parsers::WhoisNicWien].each do |klass|
      registered = parser_for(klass, 'tirol/registered.txt')
      expect(registered.registered?).to eq(true), klass.name

      available = parser_for(klass, 'tirol/available.txt')
      expect(available.status).to eq(:available), klass.name
      expect(available.registered?).to eq(false), klass.name

      reserved = parser_for(klass, 'tirol/reserved.txt')
      expect(reserved.status).to eq(:reserved), klass.name
      expect(reserved.registered?).to eq(true), klass.name
    end
  end

  it 'keeps the current absence markers for existing package-4 parsers' do
    {
      Whois::Parsers::WhoisNicCoop => 'coop_available.txt',
      Whois::Parsers::WhoisNicGd => 'gd_available.txt',
      Whois::Parsers::WhoisNicPm => 'afnic_available.txt',
      Whois::Parsers::WhoisNicFr => 'afnic_available.txt',
      Whois::Parsers::WhoisAx => 'ax_available.txt',
    }.each do |klass, fixture_name|
      parser = parser_for(klass, "existing/#{fixture_name}")
      expect(parser.available?).to eq(true), klass.name
      expect(parser.registered?).to eq(false), klass.name
    end
  end

  it 'keeps empty and ambiguous responses from becoming positive results' do
    [Whois::Parsers::WhoisNicBlog, Whois::Parsers::WhoisNicBzh].each do |klass|
      parser = klass.new(Whois::Record::Part.new(body: "Temporary registry response\n"))
      expect(parser.registered?).to eq(false), klass.name
      expect(parser.available?).to eq(false), klass.name
    end

    parser = Whois::Parsers::WhoisNgtldCn.new(Whois::Record::Part.new(body: ""))
    expect(parser.registered?).to eq(false)
    expect(parser.available?).to eq(false)
  end
end
