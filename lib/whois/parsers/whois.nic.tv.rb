require_relative 'base_icann_compliant'
require_relative 'registry_response_safety'

module Whois
  class Parsers
    # Parser for the whois.nic.tv server.
    class WhoisNicTv < BaseIcannCompliant
      include RegistryResponseSafety

      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^No Data Found\n/,
      }
    end
  end
end
