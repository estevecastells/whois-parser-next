require_relative 'base_icann_compliant'

module Whois
  class Parsers
    # The .pr endpoint currently serves the standard ICANN record format.
    class WhoisAfiliasSrsNet < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^Domain not found\.\s*$/,
      }

      def response_unavailable?
        super || content_for_scanner.match?(/\ATLD is not supported\.\s*\z/i)
      end
    end
  end
end
