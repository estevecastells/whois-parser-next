require 'spec_helper'

%w[whois.nic.ga whois.nic.net.jo whois.sx].each { |host| require "whois/parsers/#{host}" }

describe 'Registry responses observed on 2026-10-19' do
  def parser(host, body)
    Whois::Parser.parser_klass(host).new(Whois::Record::Part.new(host: host, body: body))
  end

  def reply(host, state)
    File.read(fixture('responses', 'domscan_20261019', host, "#{state}.txt"))
  end

  %w[whois.nic.ga whois.nic.net.jo whois.sx].each do |host|
    context host do
      it 'recognizes current registered and absent replies and extracts the exact domain' do
        positive = parser(host, reply(host, 'registered'))
        negative = parser(host, reply(host, 'available'))
        expect(positive.status).to eq(:registered)
        expect(positive.registered?).to eq(true)
        expect(positive.available?).to eq(false)
        expect(positive.domain).to eq({ 'whois.nic.ga' => 'example.ga', 'whois.nic.net.jo' => 'example.jo', 'whois.sx' => 'example.sx' }.fetch(host))
        expect(positive.created_on).to be_a(Time)
        expect(positive.nameservers).not_to be_empty
        expect(negative.status).to eq(:available)
        expect(negative.registered?).to eq(false)
        expect(negative.available?).to eq(true)
      end

      it 'keeps incomplete, duplicated and contradictory records unknown' do
        registered = reply(host, 'registered')
        absent = reply(host, 'available')
        [registered + absent, absent + absent, registered + registered, registered.gsub(/(?:Date de création|Creation Date):[^\n]+/, 'Creation Date: invalid')].each do |bad|
          result = parser(host, bad)
          expect(result.status).to eq(:unknown)
          expect(result.registered?).to eq(false)
          expect(result.available?).to eq(false)
        end
      end

      it 'rejects blocked, throttled and empty responses even with record fields' do
        registered = reply(host, 'registered')
        expect { parser(host, "Access denied\n" + registered).status }.to raise_error(Whois::ResponseIsUnavailable)
        expect { parser(host, "Query rate limit exceeded\n" + registered).status }.to raise_error(Whois::ResponseIsThrottled)
        expect { parser(host, '').status }.to raise_error(Whois::ResponseIsUnavailable)
      end
    end
  end

  it 'does not mistake a Jordan query echo or mismatched absence for a record' do
    ['Domain Name: google.jo', "Domain Name: google.jo\nNo match for domain \"other.jo\"\n"].each do |body|
      expect(parser('whois.nic.net.jo', body).status).to eq(:unknown)
    end
  end

  it 'rejects unknown statuses and malformed domain identities' do
    [['whois.nic.ga', 'example.ga', 'actif'], ['whois.nic.net.jo', 'example.jo', 'Active'], ['whois.sx', 'example.sx', 'clientDeleteProhibited']].each do |host, name, state|
      [reply(host, 'registered').sub(name, 'broken..invalid'), reply(host, 'registered').sub(state, 'mystery')].each do |body|
        expect(parser(host, body).status).to eq(:unknown)
      end
    end
  end
end

require 'whois/parsers/whois.isoc.org.il'

describe 'ISOC-IL incomplete reply safety' do
  def il(body)
    Whois::Parsers::WhoisIsocOrgIl.new(Whois::Record::Part.new(body: body, host: 'whois.isoc.org.il'))
  end

  it 'requires an explicit absence marker instead of treating disclaimer-only replies as available' do
    ['% The data in the WHOIS database is provided for information purposes.\n', "domain: example.il\n", "status: Transfer Locked\n"].each do |body|
      expect(il(body).status).to eq(:unknown)
      expect(il(body).registered?).to eq(false)
      expect(il(body).available?).to eq(false)
    end
    expect(il("% No data was found to match the request criteria.\n").status).to eq(:available)
  end

  it 'keeps contradictory or duplicate absence replies unknown' do
    absent = "% No data was found to match the request criteria.\n"
    [absent * 2, "domain: example.co.il\nstatus: Transfer Locked\n" + absent].each do |body|
      expect(il(body).status).to eq(:unknown)
    end
  end

  it 'rejects denied and throttled replies' do
    expect { il("Access denied\n").status }.to raise_error(Whois::ResponseIsUnavailable)
    expect { il("Query rate limit exceeded\n").status }.to raise_error(Whois::ResponseIsThrottled)
  end
end
