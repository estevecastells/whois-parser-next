require "spec_helper"
require "whois/parsers/whois.aeda.net.ae"

describe Whois::Parsers::WhoisAedaNetAe, "blacklisted response" do
  def parser_for(path)
    body = File.read(fixture("responses", "whois.aeda.net.ae/ae", path))
    described_class.new(Whois::Record::Part.new(body: body, host: "whois.aeda.net.ae"))
  end

  subject(:parser) { parser_for("response_blacklisted.txt") }

  it "is detected as throttled" do
    expect(parser.response_throttled?).to eq(true)
  end

  it "is neither registered nor available" do
    expect { parser.registered? }.to raise_error(Whois::ResponseIsThrottled)
    expect { parser.available? }.to raise_error(Whois::ResponseIsThrottled)
    expect { parser.status }.to raise_error(Whois::ResponseIsThrottled)
  end

  it "does not affect current registered and available responses" do
    expect(parser_for("current_status_registered.txt").response_throttled?).to eq(false)
    expect(parser_for("current_status_registered.txt").registered?).to eq(true)
    expect(parser_for("current_status_available.txt").response_throttled?).to eq(false)
    expect(parser_for("current_status_available.txt").available?).to eq(true)
  end
end
