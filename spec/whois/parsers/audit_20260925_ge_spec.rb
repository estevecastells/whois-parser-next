require 'spec_helper'
require 'whois/parsers/whois.nic.ge'

RSpec.describe Whois::Parsers::WhoisNicGe, 'current .ge WHOIS evidence' do
  let(:host) { 'whois.nic.ge' }

  def parser_for(response)
    body = File.read(fixture('responses', 'audit_20260925_rank122_ge', host, "#{response}.txt"))
    described_class.new(Whois::Record::Part.new(body: body, host: host))
  end

  it 'selects the parser for the IANA-listed host while the default server route stays distinct' do
    expect(Whois::Parser.parser_klass(host)).to eq(described_class)
    server = Whois::Server.find_for_domain('google.ge')
    expect(server.host).to eq('whois.registration.ge')
    expect(server).to be_a(Whois::Server::Adapters::Standard)
  end

  it 'classifies exact registered and generated-name absence evidence' do
    registered = parser_for('registered')
    absent = parser_for('available')

    expect(registered.status).to eq(:registered)
    expect(registered.registered?).to eq(true)
    expect(registered.available?).to eq(false)

    expect(absent.status).to eq(:available)
    expect(absent.registered?).to eq(false)
    expect(absent.available?).to eq(true)
  end

  it 'keeps empty, denied, and throttled responses from becoming domain results' do
    empty = described_class.new(Whois::Record::Part.new(body: '', host: host))
    denied = parser_for('denied')
    throttled = parser_for('rate_limited')

    [empty, denied].each do |parser|
      expect { parser.status }.to raise_error(Whois::ResponseIsUnavailable)
      expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable)
      expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable)
    end

    expect { throttled.status }.to raise_error(Whois::ResponseIsThrottled)
    expect { throttled.registered? }.to raise_error(Whois::ResponseIsThrottled)
    expect { throttled.available? }.to raise_error(Whois::ResponseIsThrottled)
  end

  it 'leaves conflicting, off-suffix, and unobserved status evidence unknown' do
    [parser_for('ambiguous'), parser_for('unknown_status')].each do |parser|
      expect(parser.status).to eq(:unknown)
      expect(parser.registered?).to eq(false)
      expect(parser.available?).to eq(false)
    end

    wrong_suffix = described_class.new(
      Whois::Record::Part.new(body: 'No match for "codex.invalid".\n', host: host)
    )
    expect(wrong_suffix.status).to eq(:unknown)
    expect(wrong_suffix.registered?).to eq(false)
    expect(wrong_suffix.available?).to eq(false)
  end
end
