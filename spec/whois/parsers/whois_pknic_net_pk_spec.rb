require 'spec_helper'
require 'whois/parsers/whois.pknic.net.pk'

RSpec.describe Whois::Parsers::WhoisPknicNetPk do
  def parser_for(fixture_name)
    body = File.read(fixture('responses', 'whois.pknic.net.pk', "#{fixture_name}.txt"))
    described_class.new(Whois::Record::Part.new(body: body, host: 'whois.pknic.net.pk'))
  end

  it 'maps PKNIC hostnames to this parser without claiming automatic .pk routing' do
    expect(Whois::Parser.parser_klass('whois.pknic.net.pk')).to eq(described_class)
    standard_route = Whois::Server.find_for_domain('google.pk')

    expect(standard_route).to be_a(Whois::Server::Adapters::Web)
    expect(standard_route.instance_variable_get(:@host)).to be_nil
  end

  it 'classifies the observed registered and explicitly available responses' do
    registered = parser_for('registered')
    available = parser_for('available')

    expect(registered.domain).to eq('google.pk')
    expect(registered.status).to eq(:registered)
    expect(registered.registered?).to eq(true)
    expect(registered.available?).to eq(false)

    expect(available.domain).to eq('codex-audit-20260925-7418321.pk')
    expect(available.status).to eq(:available)
    expect(available.registered?).to eq(false)
    expect(available.available?).to eq(true)
  end

  it 'requires the registry availability line and rejects contradictory evidence' do
    incomplete = parser_for('incomplete_absence')
    ambiguous = parser_for('ambiguous')

    [incomplete, ambiguous].each do |parser|
      expect(parser.status).to eq(:unknown)
      expect(parser.registered?).to eq(false)
      expect(parser.available?).to eq(false)
    end
  end

  it 'keeps empty and denied responses unavailable and throttling distinct' do
    empty = described_class.new(Whois::Record::Part.new(body: "\n", host: 'whois.pknic.net.pk'))
    denied = parser_for('denied')
    throttled = parser_for('throttled')

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
