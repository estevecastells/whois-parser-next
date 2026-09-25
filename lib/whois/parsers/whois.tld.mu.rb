require_relative 'base_icann_compliant'

module Whois
  class Parsers
    # Parser for the IANA-listed .mu WHOIS server, whois.tld.mu.
    #
    # Captures from 2026-09-25 expose ICANN-style records and the exact
    # `Domain not found.` absence marker. This host is distinct from the
    # legacy whois.nic.mu mapping in whois 6.0.3.
    class WhoisTldMu < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^[ \t]*Domain not found\.[ \t]*$/i,
      }

      property_supported :expires_on do
        node("Registry Expiry Date") { |value| parse_time(value) }
      end
    end
  end
end
