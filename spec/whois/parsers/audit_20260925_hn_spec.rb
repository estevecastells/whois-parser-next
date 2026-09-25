require 'spec_helper'
require 'whois/parsers/whois.nic.hn'

RSpec.describe Whois::Parsers::WhoisNicHn, 'current .hn WHOIS evidence' do
  let(:host) { 'whois.nic.hn' }

  def parser_for(response)
    body = File.read(fixture('responses', 'audit_20260925_rank129_hn', host, "#{response}.txt"))
    described_class.new(Whois::Record::Part.new(body: body, host: host))
  end

  it 'uses the IANA-listed standard WHOIS route' do
    server = Whois::Server.find_for_domain('google.hn')

    expect(server.host).to eq(host)
    expect(server).to be_a(Whois::Server::Adapters::Standard)
    expect(Whois::Parser.parser_klass(host)).to eq(described_class)
  end

  it 'parses the current registered record despite the Spanish registry footer' do
    parser = parser_for('registered')

    expect(parser.domain).to eq('google.hn')
    expect(parser.status).to eq(:registered)
    expect(parser.registered?).to eq(true)
    expect(parser.available?).to eq(false)
  end

  it 'recognizes the exact no-object marker when the response has no record status' do
    parser = parser_for('available')

    expect(parser.status).to eq(:available)
    expect(parser.registered?).to eq(false)
    expect(parser.available?).to eq(true)
  end

  it 'keeps a no-object marker conflicting with registration fields unknown' do
    parser = parser_for('ambiguous')

    expect(parser.status).to eq(:unknown)
    expect(parser.registered?).to eq(false)
    expect(parser.available?).to eq(false)
  end

  it 'raises on empty, denied, and rate-limited replies despite record-looking lines' do
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
end
