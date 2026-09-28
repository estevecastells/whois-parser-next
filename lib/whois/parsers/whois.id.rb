#--
# Ruby Whois
#++

require_relative 'base_icann_compliant'

module Whois
  class Parsers

    # Parser for the current whois.id registry service.
    class WhoisId < BaseIcannCompliant
      NO_RECORD_MARKER = /^The queried object does not exist: (?:DOMAIN NOT FOUND|(?:[a-z0-9-]+\.)+id)\s*$/i
      RECORD_EVIDENCE = /^(?:Domain Name|Registry Domain ID|Creation Date|Registrar|Domain Status|Name Server):[ \t]*\S/i

      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: NO_RECORD_MARKER,
      }

      property_supported :available? do
        raise ResponseIsThrottled if response_throttled?
        raise ResponseIsUnavailable if response_unavailable?

        no_record_marker_count == 1
      end

      property_supported :expires_on do
        node("Registry Expiry Date") { |value| parse_time(value) }
      end

      def response_unavailable?
        body = content_for_scanner
        marker_count = no_record_marker_count

        super || (marker_count.positive? && (marker_count != 1 || body.match?(RECORD_EVIDENCE)))
      end

      private

      def no_record_marker_count
        content_for_scanner.lines.count { |line| line.match?(NO_RECORD_MARKER) }
      end

    end

  end
end
