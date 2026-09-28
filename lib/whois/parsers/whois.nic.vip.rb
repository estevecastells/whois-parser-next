require_relative 'base_icann_compliant'

module Whois
  class Parsers
    # Identity Digital's current .vip endpoint uses the ICANN key/value
    # layout and reports an absent name as `No Data Found`.
    class WhoisNicVip < BaseIcannCompliant
      RECORD_EVIDENCE = /^(?:Domain Name|Registry Domain ID|Creation Date|Registrar|Domain Status):[ \t]*\S/i

      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^No Data Found\s*$/,
      }

      property_supported :available? do
        raise ResponseIsThrottled if response_throttled?
        raise ResponseIsUnavailable if response_unavailable?

        super()
      end

      def response_unavailable?
        body = content_for_scanner
        ambiguous_absence = body.match?(/^No Data Found\s*$/i) && body.match?(RECORD_EVIDENCE)

        super || body.match?(/^\s*access denied\b/i) ||
          ambiguous_absence
      end

      def response_throttled?
        super || content_for_scanner.match?(/^\s*too many requests\b/i)
      end
    end
  end
end
