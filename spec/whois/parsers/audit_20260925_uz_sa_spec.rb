require 'spec_helper'
require 'whois/parsers/whois.cctld.uz'
require 'whois/parsers/whois.nic.net.sa'

RSpec.describe Whois::Parsers::WhoisCctldUz, 'and .sa current WHOIS evidence' do
  it 'routes both TLDs to their IANA-listed WHOIS hosts' do
    expect(Whois::Server.find_for_domain('google.uz').host).to eq('whois.cctld.uz')
    expect(Whois::Server.find_for_domain('saudigazette.com.sa').host).to eq('whois.nic.net.sa')
  end

  def parser_for(klass, host, response)
    body = File.read(fixture('responses', 'audit_20260925_ranks104_105', host, "#{response}.txt"))
    klass.new(Whois::Record::Part.new(body: body, host: host))
  end

  {
    'whois.cctld.uz' => described_class,
    'whois.nic.net.sa' => Whois::Parsers::WhoisNicNetSa,
  }.each do |host, klass|
    describe host do
      it 'classifies the current registered record and exact authoritative absence' do
        registered = parser_for(klass, host, 'registered')
        absent = parser_for(klass, host, 'available')

        expect(registered.status).to eq(:registered)
        expect(registered.registered?).to eq(true)
        expect(registered.available?).to eq(false)

        expect(absent.status).to eq(:available)
        expect(absent.registered?).to eq(false)
        expect(absent.available?).to eq(true)
      end

      it 'raises for empty, denied, or rate-limited responses even with record-looking lines' do
        empty = klass.new(Whois::Record::Part.new(body: '', host: host))
        denied = parser_for(klass, host, 'denied')
        rate_limited = parser_for(klass, host, 'rate_limited')

        [empty, denied].each do |parser|
          expect { parser.status }.to raise_error(Whois::ResponseIsUnavailable)
          expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable)
          expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable)
        end

        expect { rate_limited.status }.to raise_error(Whois::ResponseIsThrottled)
        expect { rate_limited.registered? }.to raise_error(Whois::ResponseIsThrottled)
        expect { rate_limited.available? }.to raise_error(Whois::ResponseIsThrottled)
      end

      it 'keeps ambiguous and off-suffix markers unknown' do
        ambiguous = parser_for(klass, host, 'ambiguous')
        conflicting = parser_for(klass, host, 'conflicting') if host == 'whois.cctld.uz'
        wrong_domain = klass.new(
          Whois::Record::Part.new(
            body: "No Match for domain: codex-audit-20260925-other.invalid\n",
            host: host
          )
        )

        [ambiguous, wrong_domain, conflicting].compact.each do |parser|
          expect(parser.status).to eq(:unknown)
          expect(parser.registered?).to eq(false)
          expect(parser.available?).to eq(false)
        end
      end
    end
  end

  it 'keeps a reserved .uz name separate from registered and available' do
    body = File.read(fixture('responses', 'whois.cctld.uz', 'uz', 'property_status_reserved.txt'))
    parser = described_class.new(Whois::Record::Part.new(body: body, host: 'whois.cctld.uz'))

    expect(parser.status).to eq(:reserved)
    expect(parser.registered?).to eq(false)
    expect(parser.available?).to eq(false)
  end

  it 'keeps conflicting .sa record and no-match lines unknown' do
    parser = Whois::Parsers::WhoisNicNetSa.new(
      Whois::Record::Part.new(
        body: <<~RESPONSE,
          Domain Name: SAUDIGAZETTE.COM.SA
          No Match for domain: codex-audit-20260925-sa105.com.sa
        RESPONSE
        host: 'whois.nic.net.sa'
      )
    )

    expect(parser.status).to eq(:unknown)
    expect(parser.registered?).to eq(false)
    expect(parser.available?).to eq(false)
  end
end
