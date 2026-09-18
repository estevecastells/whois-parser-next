require_relative 'base_icann_compliant'

module Whois
  class Parsers
    # Parser for the whois.tonicregistry.to server.
    class WhoisTonicregistryTo < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^>>> Domain .+ is available for registration\n/,
      }
    end
  end
end
