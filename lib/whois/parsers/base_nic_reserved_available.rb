require_relative 'base_icann_compliant'

module Whois
  class Parsers
    # Shared parser for registries that use the ICANN response layout and
    # report an exact `Available` line for an absent object.
    class BaseNicReservedAvailable < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^Available\s*$/i,
      }

      def reserved?
        content_for_scanner.match?(/^Reserved:\s*/i)
      end
    end
  end
end
