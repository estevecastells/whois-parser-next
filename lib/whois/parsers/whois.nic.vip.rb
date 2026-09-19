require_relative 'base_icann_compliant'

module Whois
  class Parsers
    # Identity Digital's current .vip endpoint uses the ICANN key/value
    # layout and reports an absent name as `No Data Found`.
    class WhoisNicVip < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^No Data Found\s*$/,
      }
    end
  end
end
