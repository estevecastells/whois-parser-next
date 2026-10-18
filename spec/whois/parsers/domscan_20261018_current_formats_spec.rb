require 'spec_helper'

%w[whois.nic.ki whois1.nic.bi whois.nic.ci whois.ax whois.nic.ls whois.nic.gh whois.nic.do whois.dnrs.vu].each do |host|
  require "whois/parsers/#{host}"
end

describe 'Current registry formats observed on 2026-10-18' do
  def parse(host, body)
    Whois::Parser.parser_klass(host).new(Whois::Record::Part.new(host: host, body: body))
  end

  def response(host, name)
    File.read(fixture('responses', 'domscan_20261018', host, "#{name}_current.txt"))
  end

  %w[whois.nic.ki whois1.nic.bi whois.nic.ci whois.ax whois.nic.ls whois.nic.gh whois.nic.do whois.dnrs.vu].each do |host|
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

require 'whois/parsers/whois.mediaserv.net'
describe 'JWhois domain and referenced-object scope' do
  def jwhois(body)
    Whois::Parsers::WhoisMediaservNet.new(Whois::Record::Part.new(host: 'whois.mediaserv.net', body: body))
  end

  let(:registered) { "domain: example.mq\nchanged: 2026-01-01 00:00:00.0\nnameserver: ns.example.test\n" }
  let(:person_missing) { "NO OBJECT FOUND!\nobject: synthetic-contact\ntype: person\n" }
  let(:domain_missing) { "NO OBJECT FOUND!\nobject: absent-example.mq\ntype: domain\n" }

  it 'keeps a registered domain registered when referenced people are missing' do
    parser = jwhois(registered + "\n" + person_missing * 4)
    expect(parser.status).to eq(:registered)
    expect(parser.available?).to eq(false)
    expect(parser.nameservers.map(&:name)).to eq(['ns.example.test'])
  end

  it 'requires an exact domain object for authoritative absence' do
    expect(jwhois(domain_missing).status).to eq(:available)
    [person_missing, domain_missing * 2, registered + domain_missing, 'NO OBJECT FOUND!', "domain: incomplete.mq\n"].each do |body|
      expect(jwhois(body).status).to eq(:unknown)
      expect(jwhois(body).available?).to eq(false)
    end
  end
end
