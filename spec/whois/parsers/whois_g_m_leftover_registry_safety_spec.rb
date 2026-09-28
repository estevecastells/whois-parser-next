require 'spec_helper'
require 'whois/parser'
require 'whois/parsers/whois.nic.giving'
require 'whois/parsers/whois.id'
require 'whois/parsers/whois.mx'
require 'whois/parsers/whois.nic.love'
require 'whois/parsers/whois.uniregistry.net'
require 'whois/parsers/whois.nic.icu'
require 'whois/parsers/whois.nic.lat'
require 'whois/parsers/whois.afilias.net'

GM_LEFTOVER_WHOIS_PARSERS = {
  'giving' => [Whois::Parsers::WhoisNicGiving, 'whois.nic.giving', 'registered_synthetic.txt', 'available_marker.txt'],
  'id' => [Whois::Parsers::WhoisId, 'whois.id', 'registered_synthetic.txt', 'absence_synthetic.txt'],
  'mx' => [Whois::Parsers::WhoisMx, 'whois.mx', 'registered_synthetic.txt', 'available.txt'],
  'love' => [Whois::Parsers::WhoisNicLove, 'whois.nic.love', 'registered_synthetic.txt', 'available_synthetic.txt'],
  'link' => [Whois::Parsers::WhoisUniregistryNet, 'whois.uniregistry.net', 'registered_synthetic.txt', 'available_synthetic.txt'],
  'icu' => [Whois::Parsers::WhoisNicIcu, 'whois.nic.icu', 'registered_synthetic.txt', 'absence_synthetic.txt'],
  'lat' => [Whois::Parsers::WhoisNicLat, 'whois.nic.lat', 'registered_synthetic.txt', 'absence_synthetic.txt'],
}.freeze

# IANA-listed host semantics were checked on 2026-09-28. `.icu` and `.to` were
# refreshed from official hosts on 2026-09-29. Fixtures are synthetic and
# contain only parser-relevant fields and markers.
RSpec.describe Whois::Parser, 'G–M leftover WHOIS registry response safety' do
  def fixture_body(suffix, host, filename)
    File.read(fixture('responses', host, suffix, filename))
  end

  def parser(suffix, body)
    klass, host, = GM_LEFTOVER_WHOIS_PARSERS.fetch(suffix)
    klass.new(Whois::Record::Part.new(body: body, host: host))
  end

  GM_LEFTOVER_WHOIS_PARSERS.each do |suffix, (klass, host, registered_fixture, available_fixture)|
    describe ".#{suffix}" do
      it 'uses the official IANA-listed WHOIS host and matching parser' do
        server = Whois::Server.find_for_domain("google.#{suffix}")

        expect(server.host).to eq(host)
        expect(described_class.parser_klass(server.host)).to eq(klass)
      end

      it 'classifies synthetic registered and authoritative absence fixtures' do
        registered = parser(suffix, fixture_body(suffix, host, registered_fixture))
        available = parser(suffix, fixture_body(suffix, host, available_fixture))

        expect(registered.registered?).to eq(true)
        expect(registered.available?).to eq(false)
        expect(available.available?).to eq(true)
        expect(available.registered?).to eq(false)
      end

      it 'does not classify a no-record marker mixed with domain evidence as positive' do
        absent_body = fixture_body(suffix, host, available_fixture)
        contradictory = parser(suffix, "#{absent_body}\nDomain Name: synthetic.#{suffix}\n")

        if %w[giving mx].include?(suffix)
          expect(contradictory.status).to eq(:unknown)
          expect(contradictory.available?).to eq(false)
          expect(contradictory.registered?).to eq(false)
        else
          expect(contradictory.response_unavailable?).to eq(true)
          expect { contradictory.status }.to raise_error(Whois::ResponseIsUnavailable)
          expect { contradictory.available? }.to raise_error(Whois::ResponseIsUnavailable)
          expect { contradictory.registered? }.to raise_error(Whois::ResponseIsUnavailable)
        end
      end

      it 'does not classify duplicate no-record markers as authoritative absence' do
        absent_body = fixture_body(suffix, host, available_fixture)
        duplicate_marker = absent_body.lines.find do |line|
          !line.strip.empty? && !line.lstrip.start_with?('#')
        end
        contradictory = parser(suffix, "#{absent_body}\n#{duplicate_marker}")

        if %w[giving mx].include?(suffix)
          expect(contradictory.status).to eq(:unknown)
          expect(contradictory.available?).to eq(false)
          expect(contradictory.registered?).to eq(false)
        else
          expect(contradictory.response_unavailable?).to eq(true)
          expect { contradictory.status }.to raise_error(Whois::ResponseIsUnavailable)
        end
      end

      it 'does not classify an absence marker mixed with a generic denial' do
        denied = parser(suffix, "#{fixture_body(suffix, host, available_fixture)}\nAccess denied\n")

        expect(denied.response_unavailable?).to eq(true)
        expect { denied.status }.to raise_error(Whois::ResponseIsUnavailable)
        expect { denied.available? }.to raise_error(Whois::ResponseIsUnavailable)
        expect { denied.registered? }.to raise_error(Whois::ResponseIsUnavailable)
      end
    end
  end

  describe Whois::Parsers::WhoisUniregistryNet do
    it 'rejects the .link available marker when record data appears in the same response' do
      body = File.read(fixture(
        'responses', 'whois.uniregistry.net', 'link', 'ambiguous_absence_with_record_synthetic.txt'
      ))
      parser = described_class.new(Whois::Record::Part.new(body: body, host: 'whois.uniregistry.net'))

      expect(parser.response_unavailable?).to eq(true)
      expect { parser.status }.to raise_error(Whois::ResponseIsUnavailable)
    end

    it 'rejects a generic denial mixed with the .link availability marker' do
      body = File.read(fixture(
        'responses', 'whois.uniregistry.net', 'link', 'denied_available_synthetic.txt'
      ))
      parser = described_class.new(Whois::Record::Part.new(body: body, host: 'whois.uniregistry.net'))

      expect(parser.response_unavailable?).to eq(true)
      expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable)
    end
  end

  describe Whois::Parsers::WhoisAfiliasNet do
    it 'keeps the historical .info WHOIS denial unsupported and non-classifying' do
      body = File.read(fixture(
        'responses', 'whois.afilias.net', 'info', 'response_tld_unsupported_synthetic.txt'
      ))
      parser = described_class.new(Whois::Record::Part.new(body: body, host: 'whois.afilias.net'))

      expect(parser.response_unavailable?).to eq(true)
      expect { parser.status }.to raise_error(Whois::ResponseIsUnavailable)
      expect { parser.available? }.to raise_error(Whois::ResponseIsUnavailable)
      expect { parser.registered? }.to raise_error(Whois::ResponseIsUnavailable)
    end
  end

end
