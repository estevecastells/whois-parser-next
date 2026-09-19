require 'spec_helper'

require 'whois/parsers/whois.nic.cat'
require 'whois/parsers/whois.nic.gl'
require 'whois/parsers/whois.nic.vg'
require 'whois/parsers/whois.marnet.mk'
require 'whois/parsers/whois.tznic.or.tz'
require 'whois/parsers/whois.co.ug'
require 'whois/parsers/whois.nic.sn'

RSpec.describe Whois::Parser, 'ICANN DNS Magnitude ranks 151-175' do
  def parser(host, name)
    body = File.read(fixture('responses', "topdomains_151_175/#{host}/#{name}.txt"))
    Whois::Parser.parser_for(Whois::Record::Part.new(host: host, body: body))
  end

  it 'uses the live WHOIS hosts selected by the source snapshot' do
    expect(described_class.host_to_parser('whois.nic.cat')).to eq('WhoisNicCat')
    expect(described_class.host_to_parser('whois.nic.gl')).to eq('WhoisNicGl')
    expect(described_class.host_to_parser('whois.nic.vg')).to eq('WhoisNicVg')
    expect(described_class.host_to_parser('whois.marnet.mk')).to eq('WhoisMarnetMk')
    expect(described_class.host_to_parser('whois.tznic.or.tz')).to eq('WhoisTznicOrTz')
    expect(described_class.host_to_parser('whois.co.ug')).to eq('WhoisCoUg')
    expect(described_class.host_to_parser('whois.nic.sn')).to eq('WhoisNicSn')
  end

  {
    'whois.nic.cat' => 'google.cat',
    'whois.nic.gl' => 'google.gl',
    'whois.nic.vg' => 'google.vg',
    'whois.marnet.mk' => 'google.mk',
    'whois.tznic.or.tz' => 'google.tz',
    'whois.co.ug' => 'google.ug',
    'whois.nic.sn' => 'google.sn',
  }.each do |host, domain|
    it "keeps the registered response for #{host} registered" do
      response = parser(host, 'registered')

      expect(response.registered?).to eq(true)
      expect(response.available?).to eq(false)
      expect(response.domain).to eq(domain)
    end
  end

  {
    'whois.nic.cat' => :available,
    'whois.nic.gl' => :available,
    'whois.nic.vg' => :available,
    'whois.marnet.mk' => :available,
    'whois.tznic.or.tz' => :available,
    'whois.co.ug' => :available,
    'whois.nic.sn' => :available,
  }.each do |host, status|
    it "recognises the authoritative absent response for #{host}" do
      response = parser(host, 'absent')

      expect(response.status).to eq(status)
      expect(response.available?).to eq(true)
      expect(response.registered?).to eq(false)
    end
  end

  it 'does not treat the retired .shop WHOIS endpoint as a domain result' do
    body = File.read(fixture('responses', 'topdomains_151_175/whois.nic.shop/retired.txt'))

    expect(body).to include('WHOIS service has been retired')
    expect(body).to include('served via RDAP')
  end
end
