require 'spec_helper'

RSpec.describe Whois::Parser, 'current WHOIS server parser mappings' do
  mappings = {
    'au' => ['whois.auda.org.au', 'Whois::Parsers::WhoisAudaOrgAu'],
    'co' => ['whois.registry.co', 'Whois::Parsers::WhoisRegistryCo'],
    'gov' => ['whois.dotgov.gov', 'Whois::Parsers::WhoisDotgovGov'],
    'id' => ['whois.id', 'Whois::Parsers::WhoisId'],
    'ie' => ['whois.iedr.ie', 'Whois::Parsers::WhoisIedrIe'],
    'in' => ['whois.nixiregistry.in', 'Whois::Parsers::WhoisNixiregistryIn'],
    'mobi' => ['whois.afilias.net', 'Whois::Parsers::WhoisAfiliasNet'],
    'mx' => ['whois.mx', 'Whois::Parsers::WhoisMx'],
    'my' => ['whois.mynic.my', 'Whois::Parsers::WhoisMynicMy'],
    'tr' => ['whois.trabis.gov.tr', 'Whois::Parsers::WhoisTrabisGovTr'],
  }

  mappings.each do |tld, (host, class_name)|
    it "loads the current .#{tld} server parser" do
      server = Whois::Server.find_for_domain("google.#{tld}")

      expect(server.host).to eq(host)
      expect(described_class.parser_klass(host).name).to eq(class_name)
    end
  end
end
