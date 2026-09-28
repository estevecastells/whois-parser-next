require 'spec_helper'
require 'whois/parsers/whois.tcinet.ru'

RSpec.describe Whois::Parsers::WhoisTcinetRu do
  def parser_for_response(path, tld: 'xn--p1ai', host: 'whois.tcinet.ru')
    body = File.read(fixture('responses', "whois.tcinet.ru/#{tld}", path))
    described_class.new(Whois::Record::Part.new(body: body, host: host))
  end

  it 'routes .рф through the official WHOIS host and this parser' do
    server = Whois::Server.find_for_domain('example.xn--p1ai')

    expect(server.host).to eq('whois.tcinet.ru')
    expect(Whois::Parser.parser_klass(server.host)).to eq(described_class)
  end

  it 'classifies an explicit registered record and the exact no-entry reply' do
    registered = parser_for_response('status_registered.txt')
    absent = parser_for_response('status_available.txt')

    expect(registered.domain).to eq('xn----8sbc3ahklcs4adf.xn--p1ai')
    expect(registered.status).to include('REGISTERED')
    expect(registered.registered?).to eq(true)
    expect(registered.available?).to eq(false)

    expect(absent.available?).to eq(true)
    expect(absent.registered?).to eq(false)
  end

  it 'preserves valid registered state arrays for .ru and .su' do
    %w[ru su].each do |tld|
      parser = parser_for_response('status_registered.txt', tld: tld)

      expect(parser.status).to include('REGISTERED')
      expect(parser.registered?).to eq(true)
      expect(parser.available?).to eq(false)
    end
  end

  it 'keeps denied and rate-limited replies unavailable' do
    denied = parser_for_response('domscan_synthetic_denied.txt')
    throttled = parser_for_response('domscan_synthetic_throttled.txt')
    denied_with_no_entry = parser_for_response('domscan_synthetic_no_entry_with_denial.txt')
    throttled_with_no_entry = parser_for_response('domscan_synthetic_no_entry_with_throttle.txt')
    generic_access_denied = parser_for_response('domscan_synthetic_no_entry_with_generic_access_denied.txt')
    generic_too_many_requests = parser_for_response('domscan_synthetic_no_entry_with_generic_too_many_requests.txt')

    [denied, denied_with_no_entry].each do |parser|
      expect { parser.status }.to raise_error(Whois::ResponseIsUnavailable)
      expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable)
    end
    [throttled, throttled_with_no_entry].each do |parser|
      expect { parser.status }.to raise_error(Whois::ResponseIsThrottled)
      expect { parser.available? }.to raise_error(Whois::ResponseIsThrottled)
    end

    expect(generic_access_denied.response_unavailable?).to eq(true)
    expect(generic_too_many_requests.response_throttled?).to eq(true)
    expect { generic_access_denied.status }.to raise_error(Whois::ResponseIsUnavailable)
    expect { generic_access_denied.available? }.to raise_error(Whois::ResponseIsUnavailable)
    expect { generic_too_many_requests.status }.to raise_error(Whois::ResponseIsThrottled)
    expect { generic_too_many_requests.available? }.to raise_error(Whois::ResponseIsThrottled)
  end

  it 'does not infer registration or absence from incomplete or conflicting records' do
    domain_only = parser_for_response('domscan_synthetic_domain_only.txt')
    conflicting = parser_for_response('domscan_synthetic_conflicting.txt')
    conflicting_states = parser_for_response('domscan_synthetic_conflicting_states.txt')
    duplicate_domains = parser_for_response('domscan_synthetic_duplicate_domains.txt')

    expect(domain_only.status).to eq(:unknown)
    [domain_only, conflicting, conflicting_states, duplicate_domains].each do |parser|
      expect(parser.available?).to eq(false)
      expect(parser.registered?).to eq(false)
      expect(parser.status).to eq(:unknown)
    end
  end
end
