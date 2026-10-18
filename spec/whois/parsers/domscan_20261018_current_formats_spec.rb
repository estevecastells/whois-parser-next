require 'spec_helper'

%w[whois.nic.ki whois1.nic.bi whois.nic.ci whois.ax whois.nic.ls].each do |host|
  require "whois/parsers/#{host}"
end

describe 'Current registry formats observed on 2026-10-18' do
  def parse(host, body)
    Whois::Parser.parser_klass(host).new(Whois::Record::Part.new(host: host, body: body))
  end

  def response(host, name)
    File.read(fixture('responses', 'domscan_20261018', host, "#{name}_current.txt"))
  end

  %w[whois.nic.ki whois1.nic.bi whois.nic.ci whois.ax whois.nic.ls].each do |host|
    context host do
      it 'recognizes the current registered and authoritative absent shapes' do
        [[response(host, 'registered'), :registered], [response(host, 'available'), :available]].each do |body, state|
          parser = parse(host, body)
          expect(parser.status).to eq(state)
          expect(parser.registered?).to eq(state == :registered)
          expect(parser.available?).to eq(state == :available)
        end
      end

      it 'keeps contradictory, repeated and incomplete evidence unknown' do
        registered = response(host, 'registered')
        absent = response(host, 'available')
        [registered + absent, absent + absent, "Domain Name: example.invalid\nDomain Status: active https://icann.org/epp#active\n"].each do |body|
          parser = parse(host, body)
          expect(parser.status).to eq(:unknown)
          expect(parser.available?).to eq(false)
          expect(parser.registered?).to eq(false)
        end
      end

      it 'rejects explicit denials and throttling even alongside record fields' do
        registered = response(host, 'registered')
        expect { parse(host, "Access denied\n" + registered).status }.to raise_error(Whois::ResponseIsUnavailable)
        expect { parse(host, "Query rate limit exceeded\n" + registered).status }.to raise_error(Whois::ResponseIsThrottled)
        expect { parse(host, '').status }.to raise_error(Whois::ResponseIsUnavailable)
      end
    end
  end

  it 'does not accept mismatched EPP links or duplicate domain identities' do
    %w[whois.nic.ki whois1.nic.bi whois.nic.ci].each do |host|
      body = response(host, 'registered')
      [body.gsub(/#(?:ok|active)/, '#unknown'), body + body.lines.first, body.sub('example.', 'broken..')].each do |bad|
        expect(parse(host, bad).status).to eq(:unknown)
      end
    end
  end
end
