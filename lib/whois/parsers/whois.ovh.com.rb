require_relative 'base_icann_compliant'

module Whois
  class Parsers
    # Parser for the OVH WHOIS service used by .ovh.
    class WhoisOvhCom < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^% 404\s*$/i,
      }
    end
  end
end
