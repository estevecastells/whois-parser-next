require "spec_helper"
require "whois/parsers/whois.registry.qa"

describe Whois::Parsers::WhoisRegistryQa, "current responses" do
  def parser_for(file)
    body = File.binread(fixture("responses", "whois.registry.qa/qa", file))
    described_class.new(Whois::Record::Part.new(body: body, host: "whois.registry.qa"))
  end

  {
    "current_status_registered.txt" => {
      domain: "google.qa",
      status: %w[clientDeleteProhibited clientUpdateProhibited],
      registrar: "RoutEdge",
      contact: "Domain Administrator",
      nameservers: %w[ns1.google.com ns2.google.com ns3.google.com ns4.google.com],
    },
    "current_com_qa_status_registered.txt" => {
      domain: "ooredoo.com.qa",
      status: %w[ok],
      registrar: "Ooredoo QSC",
      contact: "DNS Administrator - Qtel Internet Services",
      nameservers: %w[dns2.qatar.net.qa dns1.qatar.net.qa dns3.qatar.net.qa],
    },
  }.each do |file, expected|
    it "parses the registered #{expected[:domain]} response" do
      parser = parser_for(file)

      expect(parser.domain).to eq(expected[:domain])
      expect(parser.status).to eq(expected[:status])
      expect(parser.registered?).to eq(true)
      expect(parser.available?).to eq(false)

      expect(parser.registrar).to be_a(Whois::Parser::Registrar)
      expect(parser.registrar.id).to be_nil
      expect(parser.registrar.name).to eq(expected[:registrar])

      {
        registrant_contacts: Whois::Parser::Contact::TYPE_REGISTRANT,
        technical_contacts: Whois::Parser::Contact::TYPE_TECHNICAL,
      }.each do |property, type|
        contacts = parser.public_send(property)

        expect(contacts.size).to eq(1)
        expect(contacts.first.type).to eq(type)
        expect(contacts.first.id).to be_nil
        expect(contacts.first.name).to eq(expected[:contact])
        expect(contacts.first.email).to be_nil
      end
      expect { parser.admin_contacts }.to raise_error(Whois::AttributeNotSupported)

      expect(parser.nameservers.map(&:name)).to eq(expected[:nameservers])
    end
  end

  %w[current_status_available.txt current_com_qa_status_available.txt].each do |file|
    it "classifies the #{file} no-data response as available" do
      parser = parser_for(file)

      expect(parser.available?).to eq(true)
      expect(parser.registered?).to eq(false)
      expect(parser.status).to eq([])
      expect(parser.registrar).to be_nil
      expect(parser.registrant_contacts).to eq([])
      expect(parser.technical_contacts).to eq([])
    end
  end

  it "does not read a response whose lookup banner is not followed by a record" do
    parser = described_class.new(Whois::Record::Part.new(
      body: "Welcome to Qatar Domains Registry WHOIS Lookup\r\nSomething else\r\n",
      host: "whois.registry.qa"
    ))

    expect { parser.registered? }.to raise_error(Whois::ParserError)
  end
end
