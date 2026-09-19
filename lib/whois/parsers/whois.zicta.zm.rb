require_relative 'base_icann_compliant'

module Whois
  class Parsers
    # ZICTA's current endpoint uses ICANN key/value fields and the CoCCA-style
    # no-object marker for an absent name.
    class WhoisZictaZm < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^The queried object does not exist: No Object Found\s*$/i,
      }
    end
  end
end
