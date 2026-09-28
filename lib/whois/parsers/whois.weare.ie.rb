require_relative 'base_icann_compliant'

module Whois
  class Parsers
    # Parser for the current IANA-listed .IE WHOIS host, whois.weare.ie.
    class WhoisWeareIe < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^Not found: [a-z0-9-]+\.ie\s*$/i,
      }
    end
  end
end
