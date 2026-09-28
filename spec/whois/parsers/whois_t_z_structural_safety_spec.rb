require 'spec_helper'
require 'whois/parsers/whois.nic.vip'
require 'whois/parsers/whois.nic.top'
require 'whois/parsers/whois.nic.tv'
require 'whois/parsers/whois.nic.win'
require 'whois/parsers/whois.nic.wiki'

RSpec.describe 'T–Z WHOIS suffix response safety' do
  PARSERS = {
    'vip' => Whois::Parsers::WhoisNicVip,
    'top' => Whois::Parsers::WhoisNicTop,
    'tv' => Whois::Parsers::WhoisNicTv,
    'win' => Whois::Parsers::WhoisNicWin,
    'wiki' => Whois::Parsers::WhoisNicWiki,
  }.freeze

  def parser_for(suffix, fixture_name)
    body = File.read(fixture('responses', "whois.nic.#{suffix}/#{suffix}", fixture_name))
    parser_for_body(suffix, body)
  end

  def parser_for_body(suffix, body)
    host = "whois.nic.#{suffix}"
    PARSERS.fetch(suffix).new(Whois::Record::Part.new(body: body, host: host))
  end

  it 'routes each supported suffix through the IANA-listed WHOIS host and parser' do
    PARSERS.each do |suffix, parser_class|
      server = Whois::Server.find_for_domain("google.#{suffix}")

      expect(server.host).to eq("whois.nic.#{suffix}")
      expect(Whois::Parser.parser_klass(server.host)).to eq(parser_class)
    end
  end

  PARSERS.each_key do |suffix|
    describe ".#{suffix}" do
      it 'classifies a synthetic registry-shaped record as registered' do
        parser = parser_for(suffix, 'registered_synthetic.txt')

        expect(parser.domain).to eq("synthetic.#{suffix}")
        expect(parser.registered?).to eq(true)
        expect(parser.available?).to eq(false)
      end

      it 'recognizes the synthetic authoritative absence marker' do
        parser = parser_for(suffix, 'absence_synthetic.txt')

        expect(parser.available?).to eq(true)
        expect(parser.registered?).to eq(false)
      end

      it 'keeps contradictory absence and record fields unavailable' do
        parser = parser_for(suffix, 'ambiguous_absence_with_record_synthetic.txt')

        expect(parser.response_unavailable?).to eq(true)
        expect { parser.status }.to raise_error(Whois::ResponseIsUnavailable)
        expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable)
        expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable)
      end

      it 'keeps generic denial and throttle lines from overriding the absence marker' do
        absence_fixture = fixture('responses', "whois.nic.#{suffix}/#{suffix}", 'absence_synthetic.txt')
        registered_fixture = fixture('responses', "whois.nic.#{suffix}/#{suffix}", 'registered_synthetic.txt')
        absence_body = File.read(absence_fixture)
        registered_body = File.read(registered_fixture)
        denied = parser_for_body(suffix, "#{absence_body}\nAccess denied\n")
        throttled = parser_for_body(suffix, "#{absence_body}\nToo many requests\n")
        denied_record = parser_for_body(suffix, registered_body + "\nAccess denied\n")
        throttled_record = parser_for_body(suffix, registered_body + "\nToo many requests\n")

        expect(denied.response_unavailable?).to eq(true)
        expect { denied.available? }.to raise_error(Whois::ResponseIsUnavailable)
        expect { denied.registered? }.to raise_error(Whois::ResponseIsUnavailable)

        expect { denied_record.registered? }.to raise_error(Whois::ResponseIsUnavailable)

        expect(throttled.response_throttled?).to eq(true)
        expect { throttled.available? }.to raise_error(Whois::ResponseIsThrottled)
        expect { throttled.registered? }.to raise_error(Whois::ResponseIsThrottled)
        expect { throttled_record.registered? }.to raise_error(Whois::ResponseIsThrottled)
      end
    end
  end
end
