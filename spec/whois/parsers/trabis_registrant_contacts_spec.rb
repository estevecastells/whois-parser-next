require "spec_helper"
require "whois/parsers/whois.trabis.gov.tr"

describe Whois::Parsers::WhoisTrabisGovTr, "#registrant_contacts" do
  def parser_for(file)
    body = File.read(fixture("responses", "whois.trabis.gov.tr/tr", file))
    described_class.new(Whois::Record::Part.new(body: body, host: "whois.trabis.gov.tr"))
  end

  it "parses a fully published registrant block" do
    parser = parser_for("registrant_full.txt")
    contacts = parser.registrant_contacts

    expect(contacts.size).to eq(1)
    contact = contacts.first
    expect(contact).to be_a(Whois::Parser::Contact)
    expect(contact.type).to eq(Whois::Parser::Contact::TYPE_REGISTRANT)
    expect(contact.name).to eq("Örnek Teknoloji ve Danışmanlık Ltd. Şti.")
    expect(contact.address).to eq("Ornek Mahallesi\nOrnek Sokak No: 1")
    expect(contact.city).to eq("İstanbul")
    expect(contact.country).to eq("Türkiye")
    expect(contact.email).to eq("info@example.com.tr")
    expect(contact.phone).to be_nil
    expect(contact.fax).to be_nil
    expect(parser.registered?).to eq(true)
  end

  it "keeps only the visible name when the other fields are hidden" do
    parser = parser_for("registrant_partially_hidden.txt")
    contact = parser.registrant_contacts.first

    expect(parser.domain).to eq("google.com.tr")
    expect(contact.name).to eq("Google LLC")
    expect(contact.email).to be_nil
    expect(contact.address).to be_nil
    expect(contact.city).to be_nil
    expect(contact.country).to be_nil
  end

  it "returns no contact when every registrant field is hidden" do
    parser = parser_for("registrant_hidden.txt")

    expect(parser.registrant_contacts).to eq([])
    expect(parser.registered?).to eq(true)
  end

  it "returns no contact for a no-match response" do
    parser = parser_for("status_available.txt")

    expect(parser.registrant_contacts).to eq([])
    expect(parser.available?).to eq(true)
  end

  it "does not read contacts from a throttled response" do
    part = Whois::Record::Part.new(body: "% Query rate limit exceeded\n", host: "whois.trabis.gov.tr")

    expect { described_class.new(part).registrant_contacts }.to raise_error(Whois::ResponseIsThrottled)
  end
end
