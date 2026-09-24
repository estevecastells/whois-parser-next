require 'spec_helper'
require 'whois/parsers/whois.afilias.net'

RSpec.describe Whois::Parser, 'ICANN DNS Magnitude ranks 301-1000 package 2 parser coverage' do
  let(:registered_hosts) do
    %w[
    whois.nic.beer whois.nic.bond whois.nic.foundation whois.nic.giving
    whois.nic.kn whois.nic.london whois.nic.makeup whois.nic.miami
    whois.nic.ooo whois.nic.select whois.nic.skin whois.nic.sport
    whois.nic.study whois.nic.taipei whois.nic.webcam whois.nic.yoga
    ]
  end

  let(:unsupported_hosts) do
    %w[
    whois.nic.actor whois.nic.apartments whois.nic.auction whois.nic.bargains
    whois.nic.bike whois.nic.builders whois.nic.cafe whois.nic.careers
    whois.nic.center whois.nic.city whois.nic.coach whois.nic.computer
    whois.nic.contractors whois.nic.creditcard whois.nic.dance whois.nic.deals
    whois.nic.doctor whois.nic.education whois.nic.equipment whois.nic.expert
    whois.nic.family whois.nic.fish whois.nic.florist whois.nic.furniture
    whois.nic.guru whois.nic.holdings whois.nic.house whois.nic.institute
    whois.nic.lawyer whois.nic.limited whois.nic.mba whois.nic.money
    whois.nic.pizza whois.nic.properties whois.nic.reisen whois.nic.republican
    whois.nic.rip whois.nic.salon whois.nic.schule whois.nic.support
    whois.nic.team whois.nic.tips whois.nic.town whois.nic.training
    whois.nic.vet whois.nic.wtf
    ]
  end

  def parser_for(host, fixture)
    body = File.read(fixture('responses', 'top1000_package_2', fixture))
    described_class.parser_klass(host).new(Whois::Record::Part.new(body: body, host: host))
  end

  it 'loads a parser for every host with a verified registered response' do
    registered_hosts.each do |host|
      expect(described_class.parser_klass(host)).to be < Whois::Parsers::BaseIcannCompliant
    end
  end

  it 'parses the sanitized ICANN registered evidence without false availability' do
    registered_hosts.each do |host|
      subject = parser_for(host, 'icann_registered.txt')

      expect(subject.status).to eq(:registered), host
      expect(subject.registered?).to eq(true), host
      expect(subject.available?).to eq(false), host
      expect(subject.domain).to eq('example.test'), host
      expect(subject.nameservers.map(&:name)).to eq(%w[ns1.example.test ns2.example.test]), host
    end
  end

  it 'recognizes the exact bank no-data marker as available' do
    subject = parser_for('whois.nic.bank', 'bank_available.txt')

    expect(subject.status).to eq(:available)
    expect(subject.available?).to eq(true)
    expect(subject.registered?).to eq(false)
  end

  it 'keeps an ambiguous no-object response unknown' do
    registered_hosts.each do |host|
      subject = parser_for(host, 'ambiguous.txt')

      expect(subject.status).to eq(:unknown), host
      expect(subject.available?).to eq(false), host
      expect(subject.registered?).to eq(false), host
    end
  end

  it 'raises unavailable for each explicit unsupported-TLD response' do
    unsupported_hosts.each do |host|
      subject = parser_for(host, 'tld_unsupported.txt')

      expect(subject.response_unavailable?).to eq(true), host
      expect { subject.status }.to raise_error(Whois::ResponseIsUnavailable), host
      expect { subject.available? }.to raise_error(Whois::ResponseIsUnavailable), host
      expect { subject.registered? }.to raise_error(Whois::ResponseIsUnavailable), host
    end
  end

  it 'raises unavailable for empty responses instead of inferring status' do
    (registered_hosts + ['whois.nic.bank']).each do |host|
      subject = parser_for(host, 'empty.txt')

      expect { subject.status }.to raise_error(Whois::ResponseIsUnavailable), host
      expect { subject.available? }.to raise_error(Whois::ResponseIsUnavailable), host
      expect { subject.registered? }.to raise_error(Whois::ResponseIsUnavailable), host
    end
  end

  it 'keeps retired and no-WHOIS responses unavailable' do
    {
      'whois.nic.canon' => 'canon_retired.txt',
      'whois.dominio.gq' => 'gq_no_whois.txt',
    }.each do |host, fixture_name|
      subject = parser_for(host, fixture_name)

      expect(subject.response_unavailable?).to eq(true), host
      expect { subject.status }.to raise_error(Whois::ResponseIsUnavailable), host
      expect { subject.available? }.to raise_error(Whois::ResponseIsUnavailable), host
      expect { subject.registered? }.to raise_error(Whois::ResponseIsUnavailable), host
    end
  end

  it 'keeps the current shared Afilias denial response unavailable' do
    body = File.read(fixture('responses', 'top1000_package_2', 'tld_unsupported.txt'))
    subject = Whois::Parsers::WhoisAfiliasNet.new(
      Whois::Record::Part.new(body: body, host: 'whois.afilias.net')
    )

    expect(subject.response_unavailable?).to eq(true)
    expect { subject.status }.to raise_error(Whois::ResponseIsUnavailable)
    expect { subject.available? }.to raise_error(Whois::ResponseIsUnavailable)
    expect { subject.registered? }.to raise_error(Whois::ResponseIsUnavailable)
  end
end
