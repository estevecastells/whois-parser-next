require 'spec_helper'
require 'whois/parsers/whois.registre.ma'
require 'whois/parsers/whois.nic.sh'

describe 'DomScan live registry variants observed on 2026-10-18' do
  def parser_for(host, body)
    Whois::Parser.parser_klass(host).new(Whois::Record::Part.new(host: host, body: body))
  end

  let(:active_ma) do
    File.read(fixture('responses', 'domscan_20261018', 'whois.registre.ma', 'registered_active.txt'))
  end

  it 'recognizes the documented MA active status with the observed public record fields' do
    parser = parser_for('whois.registre.ma', active_ma)
    expect(parser.status).to eq(:registered)
    expect(parser.registered?).to eq(true)
    expect(parser.available?).to eq(false)
  end

  it 'leaves conflicting and incomplete MA active replies unknown' do
    [
      active_ma + "The queried object does not exist: No Object Found\n",
      "Domain Status: active https://icann.org/epp#active\n",
      active_ma + "Domain Status: unknown https://icann.org/epp#unknown\n",
    ].each do |body|
      parser = parser_for('whois.registre.ma', body)
      expect(parser.status).to eq(:unknown)
      expect(parser.registered?).to eq(false)
      expect(parser.available?).to eq(false)
    end
  end

  it 'recognizes exact SH absence forms, including normal policy text' do
    absent = File.read(fixture('responses', 'domscan_20261018', 'whois.nic.sh', 'available.txt'))
    ["NOT FOUND\n", absent, "Domain not found.\r\n\r\nTerms of Use: Queries to the Whois services are throttled.\r\n"].each do |body|
      parser = parser_for('whois.nic.sh', body)
      expect(parser.status).to eq(:available)
      expect(parser.registered?).to eq(false)
      expect(parser.available?).to eq(true)
    end
  end

  it 'retains classification and dates for the current SH registered header' do
    body = File.read(fixture('responses', 'domscan_20261018', 'whois.nic.sh', 'registered.txt'))
    parser = parser_for('whois.nic.sh', body)
    expect(parser.status).to eq(:registered)
    expect(parser.registered?).to eq(true)
    expect(parser.available?).to eq(false)
    expect(parser.domain).to eq('nic.sh')
    expect(parser.created_on).to eq(Time.utc(2002, 7, 4, 7, 42, 26))
    expect(parser.expires_on).to eq(Time.utc(2027, 5, 1, 0, 0, 2))
  end

  it 'does not promote SH record data mixed with absence or repeated absence markers' do
    [
      "Domain not found.\nDomain Name: NIC.SH\nRegistrar: Example\n",
      "Domain not found.\nNOT FOUND\n",
      "Domain not found. More information is required\n",
    ].each do |body|
      parser = parser_for('whois.nic.sh', body)
      expect(parser.status).to eq(:unknown)
      expect(parser.registered?).to eq(false)
      expect(parser.available?).to eq(false)
    end
  end

  it 'keeps empty, denied, and throttled SH and MA responses unavailable or unknown' do
    ['whois.nic.sh', 'whois.registre.ma'].each do |host|
      ['', "Access denied\n"].each do |body|
        expect { parser_for(host, body).status }.to raise_error(Whois::ResponseIsUnavailable)
      end
      expect { parser_for(host, "Query rate limit exceeded\n" + active_ma).status }
        .to raise_error(Whois::ResponseIsThrottled)
    end
  end
end
