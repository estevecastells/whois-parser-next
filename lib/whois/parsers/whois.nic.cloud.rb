require_relative 'base_icann_compliant'
require_relative 'registry_response_safety'

module Whois
  class Parsers
    # Parser for the whois.nic.cloud server.
    class WhoisNicCloud < BaseIcannCompliant
      include RegistryResponseSafety

      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^>>> Domain \S+ is available for registration\n/,
      }
    end
  end
end
