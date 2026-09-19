require_relative 'base_icann_compliant'

module Whois
  class Parsers
    # Parser for the Identity Digital endpoint serving .ICU.
    class WhoisNicIcu < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^The queried object does not exist: DOMAIN NOT FOUND$/i,
      }
    end
  end
end
