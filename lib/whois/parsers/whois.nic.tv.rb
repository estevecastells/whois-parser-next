require_relative 'base_icann_compliant'

module Whois
  class Parsers
    # Parser for the whois.nic.tv server.
    class WhoisNicTv < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^No Data Found\n/,
      }
    end
  end
end
