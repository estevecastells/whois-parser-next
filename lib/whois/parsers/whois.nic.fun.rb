require_relative 'base_icann_compliant'

module Whois
  class Parsers
    # The .fun registry returns an ICANN key/value record and a distinct
    # availability sentence for an unregistered name.
    class WhoisNicFun < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^>>> Domain \S+ is available for registration\s*$/,
      }
    end
  end
end
