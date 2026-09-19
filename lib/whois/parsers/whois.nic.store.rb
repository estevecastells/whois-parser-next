require_relative 'base_icann_compliant'
require_relative 'registry_response_safety'

module Whois
  class Parsers
    # Parser for the Radix WHOIS service used by .store.
    class WhoisNicStore < BaseIcannCompliant
      include RegistryResponseSafety

      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^>>> Domain \S+ is available for registration\s*$/i,
      }
    end
  end
end
