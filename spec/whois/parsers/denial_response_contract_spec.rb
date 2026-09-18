require 'spec_helper'
require 'whois/parsers/whois.domainregistry.ie.rb'
require 'whois/parsers/whois.nic.es.rb'

RSpec.describe Whois::Parser, 'denial response contracts' do
  def parser_for(klass, fixture_path)
    body = File.read(fixture('responses', fixture_path))
    klass.new(Whois::Record::Part.new(body: body))
  end

  it 'does not expose nic.es authorization notices as availability answers' do
    %w[
      whois.nic.es/es/response_unavailable_ip_authorisation.txt
      whois.nic.es/es/response_unavailable_request_access.txt
    ].each do |fixture_path|
      parser = parser_for(Whois::Parsers::WhoisNicEs, fixture_path)

      expect(parser.response_unavailable?).to eq(true)
      expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable)
      expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable)
    end
  end

  it 'does not expose IEDR daily-limit notices as availability answers' do
    parser = parser_for(
      Whois::Parsers::WhoisDomainregistryIe,
      'whois.domainregistry.ie/ie/response_throttled_daily_limit.txt'
    )

    expect(parser.response_throttled?).to eq(true)
    expect { parser.available? }.to raise_error(Whois::ResponseIsThrottled)
    expect { parser.registered? }.to raise_error(Whois::ResponseIsThrottled)
  end
end
