require_relative 'base_icann_compliant'

module Whois
  class Parsers
    # Parser for the Identity Digital endpoint serving .ICU.
    class WhoisNicIcu < BaseIcannCompliant
      NO_RECORD_MARKER = /^The queried object does not exist: DOMAIN NOT FOUND\s*$/i
      RECORD_EVIDENCE = /^(?:Domain Name|Registry Domain ID|Creation Date|Registrar|Domain Status|Name Server):[ \t]*\S/i

      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: NO_RECORD_MARKER,
      }

      def response_unavailable?
        body = content_for_scanner
        marker_count = body.lines.count { |line| line.match?(NO_RECORD_MARKER) }

        super || (marker_count.positive? && (marker_count != 1 || body.match?(RECORD_EVIDENCE)))
      end
    end
  end
end
