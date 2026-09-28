require 'spec_helper'

require 'whois/parsers/whois.nic.club'
require 'whois/parsers/whois.nic.cloud'
require 'whois/parsers/whois.nic.ceo'
require 'whois/parsers/whois.auda.org.au'
require 'whois/parsers/whois.registry.click'
require 'whois/parsers/whois.nic.art'
require 'whois/parsers/whois.nic.fun'
require 'whois/parsers/whois.nic.blog'
require 'whois/parsers/whois.nic.cfd'
require 'whois/parsers/whois.nic.foundation'
require 'whois/parsers/whois.nic.best'
require 'whois/parsers/whois.nic.africa'
require 'whois/parsers/whois.nic.biz'

# These fixtures are minimal synthetic parser shapes based on bounded live
# responses recorded in the coverage audit, not raw WHOIS response captures.
RSpec.describe Whois::Parsers::WhoisNicClub, 'first-class A–F structural suffix coverage' do
  def parser_for(klass, path, host)
    body = File.read(fixture('responses', path))
    klass.new(Whois::Record::Part.new(body: body, host: host))
  end

  def parser_with_body(klass, body, host)
    klass.new(Whois::Record::Part.new(body: body, host: host))
  end

  [
    [described_class, 'topdomains_batch2/whois.nic.club/registered.txt', 'topdomains_batch2/whois.nic.club/available.txt', 'whois.nic.club', 'club'],
    [Whois::Parsers::WhoisNicCloud, 'topdomains_batch2/whois.nic.cloud/registered.txt', 'topdomains_batch2/whois.nic.cloud/available.txt', 'whois.nic.cloud', 'cloud'],
    [Whois::Parsers::WhoisNicCeo, 'domscan_a_f/ceo/registered_synthetic.txt', 'domscan_a_f/ceo/available_synthetic.txt', 'whois.nic.ceo', 'ceo'],
    [Whois::Parsers::WhoisAudaOrgAu, 'topdomains_batch2/whois.auda.org.au/registered.txt', 'topdomains_batch2/whois.auda.org.au/available.txt', 'whois.auda.org.au', 'au'],
    [Whois::Parsers::WhoisRegistryClick, 'domscan_a_f/click/registered_synthetic.txt', 'domscan_a_f/click/available_synthetic.txt', 'whois.registry.click', 'click'],
    [Whois::Parsers::WhoisNicArt, 'topdomains_276_300/whois.nic.art/registered.txt', 'topdomains_276_300/whois.nic.art/available.txt', 'whois.nic.art', 'art'],
    [Whois::Parsers::WhoisNicFun, 'topdomains_226_250/whois.nic.fun/registered.txt', 'topdomains_226_250/whois.nic.fun/available.txt', 'whois.nic.fun', 'fun'],
    [Whois::Parsers::WhoisNicBlog, 'topdomains_package_4/cira/blog_registered.txt', 'topdomains_package_4/cira/blog_available.txt', 'whois.nic.blog', 'blog'],
    [Whois::Parsers::WhoisNicCfd, 'topdomains_276_300/whois.nic.cfd/registered.txt', 'topdomains_276_300/whois.nic.cfd/available.txt', 'whois.nic.cfd', 'cfd'],
    [Whois::Parsers::WhoisNicFoundation, 'domscan_a_f/foundation/registered_synthetic.txt', 'domscan_a_f/foundation/available_synthetic.txt', 'whois.nic.foundation', 'foundation'],
    [Whois::Parsers::WhoisNicBest, 'topdomains_276_300/whois.nic.best/registered.txt', 'topdomains_276_300/whois.nic.best/available.txt', 'whois.nic.best', 'best'],
    [Whois::Parsers::WhoisNicAfrica, 'topdomains_201_250_current_20260925/whois.nic.africa/registered.txt', 'topdomains_201_250_current_20260925/whois.nic.africa/available.txt', 'whois.nic.africa', 'africa'],
    [Whois::Parsers::WhoisNicBiz, 'domscan_a_f/biz/registered_synthetic.txt', 'domscan_a_f/biz/available_synthetic.txt', 'whois.nic.biz', 'biz'],
  ].each do |klass, registered_path, available_path, host, suffix|
    describe suffix do
      it 'classifies a recorded registry record and authoritative absence' do
        registered = parser_for(klass, registered_path, host)
        available = parser_for(klass, available_path, host)

        expect(registered.registered?).to eq(true)
        expect(registered.available?).to eq(false)
        expect(available.available?).to eq(true)
        expect(available.registered?).to eq(false)
      end

      it 'does not infer status from denial, throttling, or an incomplete record' do
        registered_body = File.read(fixture('responses', registered_path))
        denied = parser_with_body(klass, "#{registered_body}\nAccess denied\n", host)
        throttled = parser_with_body(klass, "#{registered_body}\nToo many requests\n", host)
        ambiguous = parser_with_body(klass, "Domain Name: example.#{suffix}\n", host)

        expect { denied.status }.to raise_error(Whois::ResponseIsUnavailable)
        expect { throttled.status }.to raise_error(Whois::ResponseIsThrottled)
        expect(ambiguous.registered?).to eq(false)
        expect(ambiguous.available?).to eq(false)
      end
    end
  end

  it 'resolves the current IANA .click WHOIS host to its parser' do
    expect(Whois::Parser.parser_klass('whois.registry.click')).to eq(Whois::Parsers::WhoisRegistryClick)
  end

  it 'resolves the current IANA .biz WHOIS host and rejects mixed absence evidence' do
    expect(Whois::Parser.parser_klass('whois.nic.biz')).to eq(Whois::Parsers::WhoisNicBiz)

    available_body = File.read(fixture('responses', 'domscan_a_f/biz/available_synthetic.txt'))
    registered_body = File.read(fixture('responses', 'domscan_a_f/biz/registered_synthetic.txt'))
    [
      "#{available_body}#{registered_body}",
      "#{available_body}No Data Found\n",
      "#{available_body}Domain Name: example.biz\n",
    ].each do |body|
      parser = parser_with_body(Whois::Parsers::WhoisNicBiz, body, 'whois.nic.biz')
      expect(parser.status).to eq(:unknown)
      expect(parser.available?).to eq(false)
      expect(parser.registered?).to eq(false)
    end

    crlf_parser = parser_with_body(
      Whois::Parsers::WhoisNicBiz,
      "#{available_body.chomp}\r\n",
      'whois.nic.biz'
    )
    expect(crlf_parser.status).to eq(:available)
  end

  it 'keeps mixed and partial .au responses out of registered and available' do
    registered_body = File.read(fixture(
      'responses', 'topdomains_batch2/whois.auda.org.au/registered.txt'
    ))
    available_body = File.read(fixture(
      'responses', 'topdomains_batch2/whois.auda.org.au/available.txt'
    ))

    expect do
      parser_with_body(Whois::Parsers::WhoisAudaOrgAu, "#{registered_body}\nAccess denied\n", 'whois.auda.org.au').status
    end.to raise_error(Whois::ResponseIsUnavailable)
    expect do
      parser_with_body(Whois::Parsers::WhoisAudaOrgAu, "#{available_body}\nAccess denied\n", 'whois.auda.org.au').status
    end.to raise_error(Whois::ResponseIsUnavailable)
    expect do
      parser_with_body(Whois::Parsers::WhoisAudaOrgAu, "#{registered_body}\nToo many requests\n", 'whois.auda.org.au').status
    end.to raise_error(Whois::ResponseIsThrottled)
    expect do
      parser_with_body(Whois::Parsers::WhoisAudaOrgAu, "#{available_body}\nQuery rate limit exceeded\n", 'whois.auda.org.au').status
    end.to raise_error(Whois::ResponseIsThrottled)

    [
      "Domain Name: example.com.au\nStatus: clientDeleteProhibited\n",
      "Domain Name: example.com.au\nStatus: pending\nRegistry Domain ID: 123\n",
    ].each do |body|
      parser = parser_with_body(Whois::Parsers::WhoisAudaOrgAu, body, 'whois.auda.org.au')
      expect(parser.status).to eq(:unknown)
      expect(parser.registered?).to eq(false)
      expect(parser.available?).to eq(false)
    end
  end
end
