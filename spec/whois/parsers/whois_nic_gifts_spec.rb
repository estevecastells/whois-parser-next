require 'spec_helper'
require 'whois/parsers/whois.nic.gifts'

RSpec.describe Whois::Parsers::WhoisNicGifts do
  def parse(body)
    described_class.new(Whois::Record::Part.new(body: body))
  end

  it 'resolves the WHOIS gem host to this parser' do
    expect(Whois::Server.find_for_domain('example.gifts').host).to eq('whois.nic.gifts')
    expect(Whois::Parser.parser_klass('whois.nic.gifts')).to eq(described_class)
  end

  it 'raises unavailable only for the exact observed unsupported-TLD response' do
    parser = parse(File.read(fixture('responses', 'whois.nic.gifts/gifts/response_tld_unsupported.txt')))

    expect(parser.response_unavailable?).to eq(true)
    expect { parser.status }.to raise_error(Whois::ResponseIsUnavailable)
  end

  it 'does not treat unrelated or non-exact bodies as a registry denial or absence' do
    [
      'Domain not found.',
      'This response says the TLD is not supported.',
      "TLD is not supported right now.\n",
      "Access denied\nDomain not found.\n",
    ].each do |body|
      parser = parse(body)
      expect(parser.status).to eq(:unknown)
      expect(parser.available?).to eq(false)
      expect(parser.registered?).to eq(false)
      expect(parser.response_unavailable?).to eq(false)
    end
  end
end
