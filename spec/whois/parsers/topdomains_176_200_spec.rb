require 'spec_helper'

require 'whois/parsers/whois.registry.om'
require 'whois/parsers/whois.nic.ac'
require 'whois/parsers/whois.nic.dz'
require 'whois/parsers/whois.afilias-grs.info'
require 'whois/parsers/whois.nic.space'
require 'whois/parsers/whois.nic.ag'
require 'whois/parsers/whois.netcom.cm'
require 'whois/parsers/whois.uniregistry.net'
require 'whois/parsers/whois.nic.mw'

RSpec.describe Whois::Parser, 'ICANN DNS Magnitude ranks 176-200 parser coverage' do
  def parser_for(klass, host, fixture_name)
    body = File.read(fixture('responses', 'topdomains_176_200', host, fixture_name))
    klass.new(Whois::Record::Part.new(body: body, host: host))
  end

  [
    [Whois::Parsers::WhoisRegistryOm, 'whois.registry.om'],
    [Whois::Parsers::WhoisNicAc, 'whois.nic.ac'],
    [Whois::Parsers::WhoisAfiliasGrsInfo, 'whois.afilias-grs.info'],
    [Whois::Parsers::WhoisNicSpace, 'whois.nic.space'],
    [Whois::Parsers::WhoisNicAg, 'whois.nic.ag'],
    [Whois::Parsers::WhoisNetcomCm, 'whois.netcom.cm'],
    [Whois::Parsers::WhoisNicMw, 'whois.nic.mw'],
  ].each do |klass, host|
    describe klass do
      it 'classifies the registered port-43 response' do
        parser = parser_for(klass, host, 'registered.txt')

        expect(parser.registered?).to eq(true)
        expect(parser.available?).to eq(false)
      end

      it 'classifies the generated absence response as available' do
        parser = parser_for(klass, host, 'available.txt')

        expect(parser.available?).to eq(true)
        expect(parser.registered?).to eq(false)
      end
    end
  end

  it 'parses current Afilias registry fields for .ag and .vc' do
    ag = parser_for(Whois::Parsers::WhoisNicAg, 'whois.nic.ag', 'registered.txt')
    vc = parser_for(Whois::Parsers::WhoisAfiliasGrsInfo, 'whois.afilias-grs.info', 'registered.txt')

    expect(ag.domain).to eq('google.ag')
    expect(ag.nameservers.map(&:name)).to eq(%w[ns1.google.com ns4.google.com ns3.google.com ns2.google.com])
    expect(vc.domain).to eq('google.vc')
    expect(vc.nameservers.map(&:name)).to eq(%w[ns1.google.com ns4.google.com ns3.google.com ns2.google.com])
  end

  it 'normalizes the current .dz domain label' do
    parser = parser_for(Whois::Parsers::WhoisNicDz, 'whois.nic.dz', 'registered.txt')

    expect(parser.domain).to eq('google.dz')
    expect(parser.status).to eq(:registered)
  end

  it 'normalizes current .cm EPP status URLs and nameservers' do
    parser = parser_for(Whois::Parsers::WhoisNetcomCm, 'whois.netcom.cm', 'registered.txt')

    expect(parser.domain).to eq('google.cm')
    expect(parser.status).to eq(:registered)
    expect(parser.nameservers.map(&:name)).to eq(%w[ns1.google.com ns2.google.com ns3.google.com ns4.google.com])
  end

  it 'does not expose a Tucows unsupported-TLD denial as registration or availability' do
    parser = parser_for(Whois::Parsers::WhoisUniregistryNet, 'whois.uniregistry.net', 'unsupported.txt')

    expect(parser.response_unavailable?).to eq(true)
    expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable)
    expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable)
  end
end
