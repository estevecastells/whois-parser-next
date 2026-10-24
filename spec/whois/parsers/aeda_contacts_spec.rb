require "spec_helper"
require "whois/parsers/whois.aeda.net.ae"

describe Whois::Parsers::WhoisAedaNetAe, "registrar and contacts" do
  def parser_for(file)
    body = File.read(fixture("responses", "whois.aeda.net.ae/ae", file))
    described_class.new(Whois::Record::Part.new(body: body, host: "whois.aeda.net.ae"))
  end

  it "parses the registrar of a current registered response" do
    registrar = parser_for("current_contacts_registered.txt").registrar

    expect(registrar).to be_a(Whois::Parser::Registrar)
    expect(registrar.id).to eq("markmonitor")
    expect(registrar.name).to eq("MarkMonitor")
  end

  it "parses the registrant and technical contacts of a current registered response" do
    parser = parser_for("current_contacts_registered.txt")

    {
      registrant_contacts: Whois::Parser::Contact::TYPE_REGISTRANT,
      technical_contacts: Whois::Parser::Contact::TYPE_TECHNICAL,
    }.each do |property, type|
      contacts = parser.public_send(property)

      expect(contacts.size).to eq(1)
      contact = contacts.first
      expect(contact).to be_a(Whois::Parser::Contact)
      expect(contact.type).to eq(type)
      expect(contact.id).to eq("MMR-171195")
      expect(contact.name).to eq("Domain Administrator")
      expect(contact.organization).to eq("Google LLC")
      expect(contact.email).to be_nil
    end
    expect { parser.admin_contacts }.to raise_error(Whois::AttributeNotSupported)
    expect(parser.registered?).to eq(true)
  end

  it "does not read the web WHOIS notice of the legacy layout as an email" do
    parser = parser_for("status_registered.txt")

    [parser.registrant_contacts.first, parser.technical_contacts.first].each do |contact|
      expect(contact.id).to eq("GOOGLE")
      expect(contact.name).to eq("Google Inc.")
      expect(contact.organization).to be_nil
      expect(contact.email).to be_nil
    end
  end

  it "returns no registrar or contact for a no-data response" do
    parser = parser_for("current_status_available.txt")

    expect(parser.registrar).to be_nil
    expect(parser.registrant_contacts).to eq([])
    expect(parser.technical_contacts).to eq([])
    expect(parser.available?).to eq(true)
  end

  it "does not read a registrar or contacts from a blacklisted response" do
    parser = parser_for("response_blacklisted.txt")

    expect { parser.registrar }.to raise_error(Whois::ResponseIsThrottled)
    expect { parser.registrant_contacts }.to raise_error(Whois::ResponseIsThrottled)
    expect { parser.technical_contacts }.to raise_error(Whois::ResponseIsThrottled)
  end
end
