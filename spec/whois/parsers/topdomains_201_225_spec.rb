require 'spec_helper'

require 'whois/parsers/whois.nic.as'
require 'whois/parsers/whois.nic.asia'
require 'whois/parsers/whois.nic.life'
require 'whois/parsers/whois.nic.net.bw'
require 'whois/parsers/whois.nic.store'
require 'whois/parsers/whois.nic.world'
require 'whois/parsers/whois.ricta.org.rw'
require 'whois/parsers/whois.bnnic.bn'
require 'whois/parsers/whois.nic.cd'
require 'whois/parsers/whois.registry.gy'
require 'whois/parsers/whois.nic.af'
require 'whois/parsers/whois.nic.mg'

RSpec.describe Whois::Parser, 'current port-43 responses in the usage ranks 201-225 audit' do
  def parser(klass, host, path)
    body = File.read(fixture('responses', 'topdomains_201_225', host, path))
    klass.new(Whois::Record::Part.new(body: body, host: host))
  end

  {
    'cd' => ['whois.nic.cd', Whois::Parsers::WhoisNicCd],
    'rw' => ['whois.ricta.org.rw', Whois::Parsers::WhoisRictaOrgRw],
    'bw' => ['whois.nic.net.bw', Whois::Parsers::WhoisNicNetBw],
    'life' => ['whois.nic.life', Whois::Parsers::WhoisNicLife],
    'store' => ['whois.nic.store', Whois::Parsers::WhoisNicStore],
    'world' => ['whois.nic.world', Whois::Parsers::WhoisNicWorld],
  }.each do |tld, (host, klass)|
    it "loads the current .#{tld} server mapping" do
      server = Whois::Server.find_for_domain("google.#{tld}")

      expect(server.host).to eq(host)
      expect(described_class.parser_klass(host)).to eq(klass)
    end
  end

  describe Whois::Parsers::WhoisNicCd do
    it 'uses Registry Domain ID as current registered evidence' do
      registered = parser(described_class, 'whois.nic.cd', 'registered.txt')
      available = parser(described_class, 'whois.nic.cd', 'available.txt')

      expect(registered.status).to eq(:registered)
      expect(registered.registered?).to eq(true)
      expect(available.status).to eq(:available)
      expect(available.available?).to eq(true)
    end

    it 'keeps an unrecognised response unknown' do
      parser = described_class.new(
        Whois::Record::Part.new(body: "Domain Name: codex-20260919.cd\nDomain Status: Pending\n")
      )

      expect(parser.status).to eq(:unknown)
      expect(parser.registered?).to eq(false)
      expect(parser.available?).to eq(false)
    end
  end

  describe Whois::Parsers::WhoisRictaOrgRw do
    it 'parses current registered and no-object responses' do
      registered = parser(described_class, 'whois.ricta.org.rw', 'registered.txt')
      available = parser(described_class, 'whois.ricta.org.rw', 'available.txt')

      expect(registered.status).to eq(:registered)
      expect(registered.nameservers.map(&:name)).to eq(%w[ns1.google.com ns2.google.com])
      expect(available.status).to eq(:available)
    end
  end

  describe Whois::Parsers::WhoisNicStore do
    it 'parses current Radix registration and availability markers' do
      registered = parser(described_class, 'whois.nic.store', 'registered.txt')
      available = parser(described_class, 'whois.nic.store', 'available.txt')

      expect(registered.status).to eq(:registered)
      expect(registered.nameservers.map(&:name)).to eq(%w[
        ns1.googledomains.com ns2.googledomains.com
        ns3.googledomains.com ns4.googledomains.com
      ])
      expect(available.status).to eq(:available)
      expect(available.available?).to eq(true)
    end
  end

  describe Whois::Parsers::WhoisNicAsia do
    it 'parses current Name Server labels and not-found response' do
      registered = parser(described_class, 'whois.nic.asia', 'registered.txt')
      available = parser(described_class, 'whois.nic.asia', 'available.txt')

      expect(registered.registered?).to eq(true)
      expect(registered.nameservers.map(&:name)).to eq(%w[
        ns3.googledomains.com ns1.googledomains.com
        ns2.googledomains.com ns4.googledomains.com
      ])
      expect(available.available?).to eq(true)
    end
  end

  describe Whois::Parsers::WhoisBnnicBn do
    it 'does not infer registration from an unrecognised response' do
      registered = parser(described_class, 'whois.bnnic.bn', 'registered.txt')
      available = parser(described_class, 'whois.bnnic.bn', 'available.txt')

      expect(registered.status).to eq(:registered)
      expect(available.status).to eq(:available)
      expect(parser(described_class, 'whois.bnnic.bn', 'available.txt').registered?).to eq(false)
    end

    it 'keeps a denial response unknown' do
      parser = described_class.new(Whois::Record::Part.new(body: "Request denied by registry\n"))

      expect(parser.status).to eq(:unknown)
      expect(parser.registered?).to eq(false)
      expect(parser.available?).to eq(false)
    end
  end

  describe Whois::Parsers::WhoisNicAs do
    it 'requires registration evidence and recognises the current no-object marker' do
      registered = parser(described_class, 'whois.nic.as', 'registered.txt')
      available = parser(described_class, 'whois.nic.as', 'available.txt')

      expect(registered.status).to eq(:registered)
      expect(available.status).to eq(:available)
      expect(available.registered?).to eq(false)
    end

    it 'keeps an unrecognised response unknown' do
      parser = described_class.new(Whois::Record::Part.new(body: "Temporary registry response\n"))

      expect(parser.status).to eq(:unknown)
      expect(parser.registered?).to eq(false)
      expect(parser.available?).to eq(false)
    end
  end

  [
    [Whois::Parsers::WhoisRegistryGy, 'whois.registry.gy'],
    [Whois::Parsers::WhoisNicAf, 'whois.nic.af'],
    [Whois::Parsers::WhoisNicMg, 'whois.nic.mg'],
  ].each do |klass, host|
    describe klass do
      it 'recognises the current CoCCA no-object response as available' do
        available = parser(klass, host, 'available.txt')

        expect(available.status).to eq(:available)
        expect(available.registered?).to eq(false)
      end
    end
  end

  describe Whois::Parsers::WhoisNicNetBw do
    it 'keeps a prohibited-string policy response unknown' do
      policy = parser(described_class, 'whois.nic.net.bw', 'policy_denied.txt')

      expect(policy.status).to eq(:unknown)
      expect(policy.registered?).to eq(false)
      expect(policy.available?).to eq(false)
    end
  end

  [Whois::Parsers::WhoisNicLife, Whois::Parsers::WhoisNicWorld].each do |klass|
    describe klass do
      it 'raises an unavailable response for an unsupported TLD' do
        host = klass == Whois::Parsers::WhoisNicLife ? 'whois.nic.life' : 'whois.nic.world'
        expect { parser(klass, host, 'unsupported.txt').status }
          .to raise_error(Whois::ResponseIsUnavailable)
      end
    end
  end
end
