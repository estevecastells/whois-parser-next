require 'spec_helper'
require 'whois/parsers/www.gt'

describe Whois::Parsers::WwwGt do
  def parse(body)
    described_class.new(Whois::Record::Part.new(host: 'www.gt', body: body))
  end

  def registered(name = 'example.gt')
    "<html><script src='https://www.google.com/recaptcha/api.js'></script><h3>#{name}. <small><i></i> ACTIVO </small></h3></html>"
  end

  def absent(name = 'absent-example.gt')
    "<div class='alert alert-danger'><strong>#{name}.</strong> no est&aacute; registrado .</div>"
  end

  it 'recognizes exact public WHOIS states at the root and under com.gt' do
    %w[gt com.gt].each do |suffix|
      present = parse(registered("example.#{suffix}"))
      missing = parse(absent("absent-example.#{suffix}"))
      expect(present.status).to eq(:registered)
      expect(present.domain).to eq("example.#{suffix}")
      expect(present.registered?).to eq(true)
      expect(present.available?).to eq(false)
      expect(missing.status).to eq(:available)
      expect(missing.domain).to eq("absent-example.#{suffix}")
      expect(missing.registered?).to eq(false)
      expect(missing.available?).to eq(true)
    end
  end

  it 'ignores script, navigation, comments and unrelated error messages' do
    ['<script><h3>example.gt. ACTIVO</h3></script>', "<!-- #{absent} -->", '<nav>example.gt. ACTIVO</nav>', '<div>example.gt. no está registrado .</div>', "<div class='alert alert-danger'>An error occurred</div>"].each do |body|
      expect(parse(body).status).to eq(:unknown)
    end
  end

  it 'keeps mixed, duplicated, malformed and incomplete result blocks unknown' do
    [registered + absent, registered * 2, absent * 2, registered('broken..gt'), absent('other.com'), '<h3>example.gt. ACTIVO', '<h3' * 200_000, registered.sub('ACTIVO', 'PENDIENTE')].each do |body|
      result = parse(body)
      expect(result.status).to eq(:unknown)
      expect(result.registered?).to eq(false)
      expect(result.available?).to eq(false)
    end
  end

  it 'does not classify an active challenge, denial or throttle as a record' do
    ["<cap-widget></cap-widget>" + registered, "<div class='g-recaptcha'></div>" + registered, 'Access denied'].each do |body|
      expect { parse(body).status }.to raise_error(Whois::ResponseIsUnavailable)
    end
    expect { parse('Query rate limit exceeded').status }.to raise_error(Whois::ResponseIsThrottled)
    expect { parse('').status }.to raise_error(Whois::ResponseIsUnavailable)
  end
end
