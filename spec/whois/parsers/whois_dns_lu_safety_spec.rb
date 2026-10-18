require 'spec_helper'
require 'whois/parsers/whois.dns.lu'

describe Whois::Parsers::WhoisDnsLu do
  def parse(body)
    described_class.new(Whois::Record::Part.new(body: body))
  end

  # Minimal synthetic shapes based on the 2026-10-17 production observation.
  # Registry boilerplate and contacts are deliberately not reproduced.
  let(:record) { "domainname:     example.lu\ndomaintype:     ACTIVE\nnserver:        ns.example.test\n" }

  it 'recognizes the current active record, including CRLF and a contact-form comment' do
    body = record + "% a form to contact domain operator is available.\n"
    [body, body.gsub("\n", "\r\n")].each do |input|
      parser = parse(input)
      expect(parser.status).to eq(:registered)
      expect(parser.registered?).to be(true)
      expect(parser.available?).to be(false)
    end
  end

  it 'keeps the existing authoritative absence fixture available' do
    parser = parse(File.read(fixture('responses', 'whois.dns.lu/lu/status_available.txt')))
    expect(parser.status).to eq(:available)
    expect(parser.available?).to be(true)
    expect(parser.registered?).to be(false)
  end

  [
    'domainname: example.lu',
    'domaintype: ACTIVE',
    '% a form is available.',
  ].each do |body|
    it "keeps #{body.inspect} unknown" do
      parser = parse(body)
      expect(parser.status).to eq(:unknown)
      expect(parser.registered?).to be(false)
      expect(parser.available?).to be(false)
    end
  end

  ['% No such domain'].each do |marker|
    it "rejects an active record mixed with #{marker.inspect}" do
      parser = parse(record + marker + "\n")
      expect(parser.status).to eq(:unknown)
      expect(parser.registered?).to be(false)
      expect(parser.available?).to be(false)
    end
  end

  [
    ['', Whois::ResponseIsUnavailable],
    ['%% Maximum query rate reached', Whois::ResponseIsThrottled],
    ["%% Maximum query rate reached\n% No such domain", Whois::ResponseIsThrottled],
    ["Access denied\n% No such domain", Whois::ResponseIsUnavailable],
  ].each do |body, error|
    it "preserves #{error} for #{body.inspect}" do
      [:status, :registered?, :available?].each do |method|
        expect { parse(body).public_send(method) }.to raise_error(error)
      end
    end
  end

  [
    ['%% Maximum query rate reached', Whois::ResponseIsThrottled],
    ['Access denied', Whois::ResponseIsUnavailable],
  ].each do |marker, error|
    it "rejects a record mixed with #{marker.inspect}" do
      [:status, :registered?, :available?].each do |method|
        expect { parse(record + marker + "\n").public_send(method) }.to raise_error(error)
      end
    end
  end
end
