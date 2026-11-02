require "spec_helper"
require "timeout"
require "whois/scanners/verisign"
require "whois/scanners/whois.cira.ca"
require "whois/scanners/whois.sx"
require "whois/scanners/whois.domainregistry.ie"
require "whois/scanners/whois.ati.tn"
require "whois/scanners/base_afilias"
require "whois/scanners/whois.pir.org"
require "whois/scanners/iana"
require "whois/parsers/whois.verisign-grs.com"

# Truncated or hostile replies must end in a parse error or a result, never an
# endless loop. Every example runs under a deadline so a regression fails
# instead of hanging the suite.
describe "scanner progress on untrusted responses" do
  def within_deadline(&block)
    Timeout.timeout(5, &block)
  end

  {
    "Verisign disclaimer" => [Whois::Scanners::Verisign, {}, "TERMS OF USE:"],
    "Verisign notice" => [Whois::Scanners::Verisign, {}, "NOTICE:"],
    "Verisign disclaimer after a record line" => [Whois::Scanners::Verisign, {}, "   Domain Name: EXAMPLE.COM\nTERMS OF USE:"],
    "CIRA disclaimer" => [Whois::Scanners::WhoisCiraCa, {}, "% Use of CIRA"],
    "SX legal statement" => [Whois::Scanners::WhoisSx, {}, "% WHOIS LEGAL STATEMENT"],
    ".ie disclaimer" => [Whois::Scanners::WhoisDomainregistryIe, {}, "% Rights restricted by copyright"],
    ".ie application pending" => [Whois::Scanners::WhoisDomainregistryIe, {}, "% Application Pending"],
    ".ie contact" => [Whois::Scanners::WhoisDomainregistryIe, {}, "person:"],
    "ATI disclaimer" => [Whois::Scanners::WhoisAtiTn, {}, "All rights reserved"],
    "PIR disclaimer" => [Whois::Scanners::WhoisPirOrg, {}, "Access to"],
    "Afilias configured disclaimer" => [
      Whois::Scanners::BaseAfilias,
      { pattern_disclaimer: /^DotAsia WHOIS LEGAL STATEMENT AND TERMS & CONDITIONS:/ },
      "DotAsia WHOIS LEGAL STATEMENT AND TERMS & CONDITIONS:",
    ],
  }.each do |name, (scanner, settings, body)|
    it "rejects a #{name} truncated before its final newline" do
      within_deadline do
        expect { scanner.new(settings).parse(body) }.to raise_error(Whois::ParserError)
      end
    end
  end

  it "still parses the same disclaimer when the line is terminated" do
    ast = within_deadline { Whois::Scanners::Verisign.new.parse("TERMS OF USE: You are not authorized.\n") }
    expect(ast["Disclaimer"]).to eq("TERMS OF USE: You are not authorized.")
  end

  it "surfaces the truncated Verisign reply as a ParserError through the public parser" do
    part = Whois::Record::Part.new(body: "TERMS OF USE:", host: "whois.verisign-grs.com")
    parser = Whois::Parsers::WhoisVerisignGrsCom.new(part)
    within_deadline do
      expect { parser.available? }.to raise_error(Whois::ParserError)
    end
  end

  ["()|^", "(?=(.*))|.*"].each do |key|
    it "treats an IANA field key #{key.inspect} as text, not a pattern" do
      body = "domain:       EXAMPLE\n#{key}: first\nnext:   value\n\n"
      ast = within_deadline { Whois::Scanners::Iana.new.parse(body) }
      expect(ast["domain"]).to include(key => "first", "next" => "value")
    end
  end

  it "keeps joining IANA multi-line values under a literal key" do
    body = "contact:      administrative\nname:         Example\naddress:      Line 1\naddress:      Line 2\n\n"
    ast = within_deadline { Whois::Scanners::Iana.new.parse(body) }
    expect(ast["administrative"]["address"]).to eq("Line 1\nLine 2")
  end
end
