require 'spec_helper'
require 'whois/parsers/whois.nic.cloud'
require 'whois/parsers/whois.nixiregistry.in'
require 'whois/parsers/whois.nic.tv'
require 'whois/parsers/whois.nic.club'
require 'whois/parsers/whois.tonicregistry.to'
require 'whois/parsers/whois.auda.org.au'
require 'whois/parsers/whois.trabis.gov.tr'
require 'whois/parsers/whois.nic.ms'
require 'whois/parsers/whois.cira.ca'
require 'whois/parsers/whois.fi'
require 'whois/parsers/whois.nic.tech'
require 'whois/parsers/whois.domain-registry.nl'
require 'whois/parsers/whois.nic.at'

describe 'top domains batch 2 parser coverage' do
  def parser_for(klass, host, file)
    part = Whois::Record::Part.new(
      body: File.read(fixture('responses', 'topdomains_batch2', host, file)),
      host: host
    )
    klass.new(part)
  end

  [
    [Whois::Parsers::WhoisNicCloud, 'whois.nic.cloud'],
    [Whois::Parsers::WhoisNixiregistryIn, 'whois.nixiregistry.in'],
    [Whois::Parsers::WhoisNicTv, 'whois.nic.tv'],
    [Whois::Parsers::WhoisNicClub, 'whois.nic.club'],
    [Whois::Parsers::WhoisTonicregistryTo, 'whois.tonicregistry.to'],
  ].each do |klass, host|
    describe klass do
      it 'classifies the registered response' do
        parser = parser_for(klass, host, 'registered.txt')
        expect(parser.domain).to match(/\A(?:google\.|go\.)/)
        expect(parser.registered?).to eq(true)
        expect(parser.available?).to eq(false)
      end

      it 'classifies the registry availability response' do
        parser = parser_for(klass, host, 'available.txt')
        expect(parser.available?).to eq(true)
        expect(parser.registered?).to eq(false)
      end
    end
  end

  describe Whois::Parsers::WhoisAudaOrgAu do
    it 'parses the current registered and available responses' do
      registered = parser_for(described_class, 'whois.auda.org.au', 'registered.txt')
      available = parser_for(described_class, 'whois.auda.org.au', 'available.txt')
      expect(registered.registered?).to eq(true)
      expect(registered.nameservers.map(&:name)).to eq(%w[ns1.google.com ns2.google.com])
      expect(available.available?).to eq(true)
    end
  end

  describe Whois::Parsers::WhoisTrabisGovTr do
    it 'parses the Turkish registered response' do
      parser = parser_for(described_class, 'whois.trabis.gov.tr', 'registered.txt')
      expect(parser.domain).to eq('google.com.tr')
      expect(parser.status).to eq(:registered)
      expect(parser.nameservers.map(&:name)).to eq(%w[ns4.google.com ns1.google.com])
    end

    it 'parses the Turkish no-match response as available' do
      parser = parser_for(described_class, 'whois.trabis.gov.tr', 'available.txt')
      expect(parser.available?).to eq(true)
      expect(parser.registered?).to eq(false)
    end
  end

  describe Whois::Parsers::WhoisNicMs do
    it 'accepts current EPP status URLs and active status' do
      parser = parser_for(described_class, 'whois.nic.ms', 'current_registered.txt')
      expect(parser.status).to eq(:registered)
      expect(parser.registered?).to eq(true)
    end

    it 'accepts the current no-object response' do
      parser = parser_for(described_class, 'whois.nic.ms', 'current_available.txt')
      expect(parser.status).to eq(:available)
      expect(parser.available?).to eq(true)
    end
  end

  describe Whois::Parsers::WhoisCiraCa do
    it 'accepts current ICANN labels and EPP statuses' do
      parser = parser_for(described_class, 'whois.cira.ca', 'current_registered.txt')
      expect(parser.domain).to eq('google.ca')
      expect(parser.status).to eq(:registered)
      expect(parser.created_on).to be_a(Time)
      expect(parser.nameservers.map(&:name)).to eq(['ns1.google.com'])
    end

    it 'classifies the current not-found response as available' do
      parser = parser_for(described_class, 'whois.cira.ca', 'current_available.txt')
      expect(parser.status).to eq(:available)
      expect(parser.available?).to eq(true)
    end
  end

  describe Whois::Parsers::WhoisFi do
    it 'parses padded current labels and section headings' do
      parser = parser_for(described_class, 'whois.fi', 'current_registered.txt')
      expect(parser.domain).to eq('google.fi')
      expect(parser.status).to eq(:registered)
      expect(parser.nameservers.map(&:name)).to eq(%w[ns1.google.com ns2.google.com])
    end

    it 'classifies the current not-found response as available' do
      parser = parser_for(described_class, 'whois.fi', 'current_available.txt')
      expect(parser.status).to eq(:available)
      expect(parser.available?).to eq(true)
    end
  end

  describe Whois::Parsers::WhoisNicTech do
    it 'classifies the current availability wording' do
      parser = parser_for(described_class, 'whois.nic.tech', 'current_available.txt')
      expect(parser.available?).to eq(true)
      expect(parser.registered?).to eq(false)
    end
  end

  describe Whois::Parsers::WhoisDomainRegistryNl do
    it 'parses current domain and date labels' do
      parser = parser_for(described_class, 'whois.domain-registry.nl', 'current_registered.txt')
      expect(parser.domain).to eq('google.nl')
      expect(parser.created_on).to be_a(Time)
      expect(parser.updated_on).to be_a(Time)
    end
  end

  describe Whois::Parsers::WhoisNicAt do
    it 'parses the current domain label' do
      parser = parser_for(described_class, 'whois.nic.at', 'current_registered.txt')
      expect(parser.domain).to eq('google.at')
    end
  end
end
