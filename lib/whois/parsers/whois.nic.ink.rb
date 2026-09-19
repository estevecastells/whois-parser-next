require_relative 'base_icann_compliant'

module Whois
  class Parsers
    # Parser for the Identity Digital endpoint serving .INK.
    class WhoisNicInk < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^No Data Found$/i,
      }
    end
  end
end
