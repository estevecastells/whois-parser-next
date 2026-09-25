require 'spec_helper'
require 'whois/parsers/whois.nic.ch'

RSpec.describe Whois::Parsers::WhoisNicCh, 'response safety' do
  # Observed from whois.nic.ch:43 on 2026-09-25; the fixture contains only the
  # registry's generic client-denial response, with no queried-domain data.
  def parser_for(name)
    body = File.read(fixture('responses', 'whois.nic.ch/ch', "#{name}.txt"))
    described_class.new(Whois::Record::Part.new(body: body))
  end

  it 'keeps the current port-43 client denial unknown' do
    parser = parser_for('response_denied')

    expect(parser.response_unavailable?).to eq(true)
    expect { parser.status }.to raise_error(Whois::ResponseIsUnavailable)
    expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable)
    expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable)
  end

  it 'keeps an empty response unknown' do
    parser = parser_for('response_empty')

    expect(parser.response_incomplete?).to eq(true)
    expect(parser.response_unavailable?).to eq(true)
    expect { parser.status }.to raise_error(Whois::ResponseIsUnavailable)
    expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable)
  end

  it 'does not treat an unrecognized non-empty response as registration' do
    parser = parser_for('response_ambiguous')

    expect(parser.response_unavailable?).to eq(false)
    expect { parser.status }.to raise_error(Whois::ParserError, /Unable to parse \.ch response status/)
    expect { parser.registered? }.to raise_error(Whois::ParserError, /Unable to parse \.ch response status/)
  end
end
