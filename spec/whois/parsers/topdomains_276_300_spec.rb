require 'spec_helper'

require 'whois/parsers/whois.nic.re'
require 'whois/parsers/whois.nic.wf'
require 'whois/parsers/whois.nic.website'
require 'whois/parsers/whois.nic.name'
require 'whois/parsers/whois.nic.design'
require 'whois/parsers/whois.nic.win'
require 'whois/parsers/whois.nic.art'
require 'whois/parsers/whois.ovh.com'
require 'whois/parsers/whois.nic.best'
require 'whois/parsers/whois.nic.cfd'
require 'whois/parsers/whois.uniregistry.net'
require 'whois/parsers/whois.nic.plus'
require 'whois/parsers/whois.nic.rocks'
require 'whois/parsers/whois.nic.domains'
require 'whois/parsers/whois.nic.ltd'
require 'whois/parsers/whois.nic.pub'
require 'whois/parsers/whois.nic.ninja'
require 'whois/parsers/whois.nic.group'
require 'whois/parsers/whois.nic.studio'
require 'whois/parsers/whois.nic.run'
require 'whois/parsers/whois.nic.today'
require 'whois/parsers/whois.nic.market'

RSpec.describe Whois::Parser, 'ICANN DNS Magnitude ranks 276-300 parser coverage' do
  def fixture_root
    'responses/topdomains_276_300'
  end

  def parser_for(klass, host, fixture_name)
    body = File.read(fixture(fixture_root, host, fixture_name))
    klass.new(Whois::Record::Part.new(body: body, host: host))
  end

  it 'keeps the snapshot source mappings explicit for delegated and undelegated entries' do
    {
      'page' => 'whois.nic.google',
      're' => 'whois.nic.re',
      'plus' => 'whois.nic.plus',
      'rocks' => 'whois.nic.rocks',
      'website' => 'whois.nic.website',
      'domains' => 'whois.nic.domains',
      'wf' => 'whois.nic.wf',
      'name' => 'whois.nic.name',
      'ltd' => 'whois.nic.ltd',
      'pub' => 'whois.nic.pub',
      'design' => 'whois.nic.design',
      'ninja' => 'whois.nic.ninja',
      'group' => 'whois.nic.group',
      'art' => 'whois.nic.art',
      'studio' => 'whois.nic.studio',
      'run' => 'whois.nic.run',
      'lol' => 'whois.uniregistry.net',
      'win' => 'whois.nic.win',
      'ovh' => 'whois.ovh.com',
      'best' => 'whois.nic.best',
      'today' => 'whois.nic.today',
      'cfd' => 'whois.nic.cfd',
      'market' => 'whois.nic.market',
      'help' => 'whois.uniregistry.net',
    }.each do |tld, host|
      expect(Whois::Server.find_for_domain("google.#{tld}").host).to eq(host), tld
    end

    expect(Whois::Server.find_for_domain('google.server')).to be_nil
  end

  [
    [Whois::Parsers::WhoisNicRe, 'whois.nic.re'],
    [Whois::Parsers::WhoisNicWf, 'whois.nic.wf'],
    [Whois::Parsers::WhoisNicWebsite, 'whois.nic.website'],
    [Whois::Parsers::WhoisNicName, 'whois.nic.name'],
    [Whois::Parsers::WhoisNicDesign, 'whois.nic.design'],
    [Whois::Parsers::WhoisNicWin, 'whois.nic.win'],
    [Whois::Parsers::WhoisNicArt, 'whois.nic.art'],
    [Whois::Parsers::WhoisOvhCom, 'whois.ovh.com'],
    [Whois::Parsers::WhoisNicBest, 'whois.nic.best'],
    [Whois::Parsers::WhoisNicCfd, 'whois.nic.cfd'],
  ].each do |klass, host|
    describe klass do
      it 'classifies the observed registered response' do
        parser = parser_for(klass, host, 'registered.txt')

        expect(parser.registered?).to eq(true)
        expect(parser.available?).to eq(false)
      end

      it 'classifies the generated authoritative absence response as available' do
        parser = parser_for(klass, host, 'available.txt')

        expect(parser.available?).to eq(true)
        expect(parser.registered?).to eq(false)
      end
    end
  end

  it 'parses nameservers from the current CentralNic and Radix records' do
    art = parser_for(Whois::Parsers::WhoisNicArt, 'whois.nic.art', 'registered.txt')
    website = parser_for(Whois::Parsers::WhoisNicWebsite, 'whois.nic.website', 'registered.txt')

    expect(art.nameservers.map(&:name)).to eq(%w[
      ns2.googledomains.com ns4.googledomains.com
      ns3.googledomains.com ns1.googledomains.com
    ])
    expect(website.nameservers.map(&:name)).to eq(%w[
      ns1.google.com ns2.google.com ns3.google.com ns4.google.com
    ])
  end

  it 'does not expose the shared Uniregistry denial as registration or availability' do
    parser = parser_for(
      Whois::Parsers::WhoisUniregistryNet,
      'whois.uniregistry.net',
      'unsupported.txt'
    )

    expect(parser.response_unavailable?).to eq(true)
    expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable)
    expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable)
  end

  it 'keeps Identity Digital unsupported-TLD responses explicitly unavailable' do
    [
      [Whois::Parsers::WhoisNicPlus, 'whois.nic.plus'],
      [Whois::Parsers::WhoisNicRocks, 'whois.nic.rocks'],
      [Whois::Parsers::WhoisNicDomains, 'whois.nic.domains'],
      [Whois::Parsers::WhoisNicLtd, 'whois.nic.ltd'],
      [Whois::Parsers::WhoisNicPub, 'whois.nic.pub'],
      [Whois::Parsers::WhoisNicNinja, 'whois.nic.ninja'],
      [Whois::Parsers::WhoisNicGroup, 'whois.nic.group'],
      [Whois::Parsers::WhoisNicStudio, 'whois.nic.studio'],
      [Whois::Parsers::WhoisNicRun, 'whois.nic.run'],
      [Whois::Parsers::WhoisNicToday, 'whois.nic.today'],
      [Whois::Parsers::WhoisNicMarket, 'whois.nic.market'],
    ].each do |klass, host|
      body = File.read(fixture(fixture_root, 'identity_digital_unsupported.txt'))
      parser = klass.new(Whois::Record::Part.new(body: body, host: host))

      expect(parser.response_unavailable?).to eq(true), host
      expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable), host
      expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable), host
    end
  end
end
