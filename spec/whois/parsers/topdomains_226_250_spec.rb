require 'spec_helper'

require 'whois/parsers/whois.zicta.zm'
require 'whois/parsers/whois.nic.vip'
require 'whois/parsers/whois.nic.tg'
require 'whois/parsers/whois.nic.tl'
require 'whois/parsers/whois.nic.sl'
require 'whois/parsers/whois.nic.video'
require 'whois/parsers/whois.nic.sm'
require 'whois/parsers/whois.nic.net.sb'
require 'whois/parsers/whois.vunic.vu'
require 'whois/parsers/whois.usp.ac.fj'
require 'whois/parsers/whois.nic.chat'
require 'whois/parsers/whois.je'
require 'whois/parsers/whois.afilias-srs.net'
require 'whois/parsers/whois.nic.bj'
require 'whois/parsers/whois.nic.ht'
require 'whois/parsers/whois.tcinet.ru'
require 'whois/parsers/whois.nic.fun'

RSpec.describe Whois::Parser, 'ICANN DNS Magnitude ranks 226-250 audit' do
  def parser_for(klass, host, fixture_name)
    path = fixture('responses', 'topdomains_226_250', host, fixture_name)
    klass.new(Whois::Record::Part.new(body: File.read(path), host: host))
  end

  it 'keeps the source rank mapping tied to the current whois server data' do
    expected_hosts = {
      'zm' => 'whois.zicta.zm',
      'vip' => 'whois.nic.vip',
      'tg' => 'whois.nic.tg',
      'tl' => 'whois.nic.tl',
      'sl' => 'whois.nic.sl',
      'video' => 'whois.nic.video',
      'sm' => 'whois.nic.sm',
      'sb' => 'whois.nic.net.sb',
      'vu' => 'vunic.vu',
      'fj' => 'whois.usp.ac.fj',
      'chat' => 'whois.nic.chat',
      'je' => 'whois.je',
      'pr' => 'whois.afilias-srs.net',
      'bj' => 'whois.nic.bj',
      'ht' => 'whois.nic.ht',
      'su' => 'whois.tcinet.ru',
      'fun' => 'whois.nic.fun',
    }

    expected_hosts.each do |tld, host|
      server = Whois::Server.find_for_domain("google.#{tld}")

      expect(server.host).to eq(host)
      expect(described_class.parser_klass(host)).to be < Whois::Parsers::Base
    end
  end

  it 'keeps web-only and no-adapter source rows out of port-43 parsing' do
    {
      'jm' => Whois::Server::Adapters::None,
      'pg' => Whois::Server::Adapters::None,
      'bs' => Whois::Server::Adapters::Web,
      'ls' => Whois::Server::Adapters::Web,
      'gm' => Whois::Server::Adapters::Web,
      'gp' => Whois::Server::Adapters::Web,
      'pn' => Whois::Server::Adapters::Web,
    }.each do |tld, adapter|
      server = Whois::Server.find_for_domain("google.#{tld}")

      expect(server).to be_a(adapter)
    end

    expect(Whois::Server.find_for_domain('google.home')).to be_nil
  end

  [
    [Whois::Parsers::WhoisZictaZm, 'whois.zicta.zm'],
    [Whois::Parsers::WhoisNicVip, 'whois.nic.vip'],
    [Whois::Parsers::WhoisNicTg, 'whois.nic.tg'],
    [Whois::Parsers::WhoisNicTl, 'whois.nic.tl'],
    [Whois::Parsers::WhoisNicSl, 'whois.nic.sl'],
    [Whois::Parsers::WhoisNicNetSb, 'whois.nic.net.sb'],
    [Whois::Parsers::WhoisAfiliasSrsNet, 'whois.afilias-srs.net'],
    [Whois::Parsers::WhoisJe, 'whois.je'],
    [Whois::Parsers::WhoisNicFun, 'whois.nic.fun'],
  ].each do |klass, host|
    describe klass do
      it 'classifies the captured registered response' do
        subject = parser_for(klass, host, 'registered.txt')

        expect(subject.registered?).to eq(true)
        expect(subject.available?).to eq(false)
      end

      it 'classifies the captured authoritative absence response as available' do
        subject = parser_for(klass, host, 'available.txt')

        expect(subject.available?).to eq(true)
        expect(subject.registered?).to eq(false)
      end
    end
  end

  it 'preserves the Togo record fields from the current aligned response' do
    subject = parser_for(Whois::Parsers::WhoisNicTg, 'whois.nic.tg', 'registered.txt')

    expect(subject.domain).to eq('google.tg')
    expect(subject.nameservers.map(&:name)).to eq(%w[ns1.google.com ns2.google.com ns3.google.com ns4.google.com])
  end

  it 'keeps the ZICTA registered probe distinct from its absent Google-shaped probe' do
    subject = parser_for(Whois::Parsers::WhoisZictaZm, 'whois.zicta.zm', 'registered.txt')

    expect(subject.domain).to eq('zicta.zm')
    expect(subject.status).to eq(:registered)
  end

  it 'normalizes the Jersey domain and nameservers' do
    subject = parser_for(Whois::Parsers::WhoisJe, 'whois.je', 'registered.txt')

    expect(subject.domain).to eq('google.je')
    expect(subject.created_on.strftime('%Y-%m-%d')).to eq('2002-10-31')
    expect(subject.nameservers.map(&:name)).to eq(%w[ns1.google.com ns2.google.com ns3.google.com ns4.google.com])
  end

  [
    [Whois::Parsers::WhoisNicVideo, 'whois.nic.video'],
    [Whois::Parsers::WhoisNicChat, 'whois.nic.chat'],
  ].each do |klass, host|
    it "does not classify #{host}'s explicit unsupported response as a domain result" do
      subject = parser_for(klass, host, 'unsupported.txt')

      expect(subject.response_unavailable?).to eq(true)
      expect { subject.status }.to raise_error(Whois::ResponseIsUnavailable)
      expect { subject.available? }.to raise_error(Whois::ResponseIsUnavailable)
      expect { subject.registered? }.to raise_error(Whois::ResponseIsUnavailable)
    end
  end

  [
    [Whois::Parsers::WhoisNicSm, 'whois.nic.sm', 'service-unavailable.txt'],
    [Whois::Parsers::WhoisVunicVu, 'whois.vunic.vu', 'invalid.txt'],
  ].each do |klass, host, fixture_name|
    it "does not classify #{host}'s outage or invalid-query response as a domain result" do
      subject = parser_for(klass, host, fixture_name)

      expect(subject.response_unavailable?).to eq(true)
      expect { subject.status }.to raise_error(Whois::ResponseIsUnavailable)
      expect { subject.available? }.to raise_error(Whois::ResponseIsUnavailable)
      expect { subject.registered? }.to raise_error(Whois::ResponseIsUnavailable)
    end
  end
end
