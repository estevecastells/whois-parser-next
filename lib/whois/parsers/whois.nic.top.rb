require_relative 'base_top1000_icann'

module Whois
  class Parsers
    # The .top registry uses the shared ICANN record shape and returns the full
    # queried .top name in its exact no-record response.
    class WhoisNicTop < BaseTop1000Icann
      RECORD_EVIDENCE = /^(?:Domain Name|Registry Domain ID|Creation Date|Registrar|Domain Status):[ \t]*\S/i
      NO_RECORD_MARKER = /
        ^The\ queried\ object\ does\ not\ exist:\s+
        (?:DOMAIN\ NOT\ FOUND|no\ matching\ objects\ found|
          (?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)*
          [A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.top)
        \s*$
      /ix

      property_supported :available? do
        raise ResponseIsThrottled if response_throttled?
        raise ResponseIsUnavailable if response_unavailable?

        super() || content_for_scanner.match?(NO_RECORD_MARKER)
      end

      def response_unavailable?
        body = content_for_scanner
        ambiguous_absence = body.match?(NO_RECORD_MARKER) && body.match?(RECORD_EVIDENCE)

        super || body.match?(/^\s*access denied\b/i) ||
          ambiguous_absence
      end

      def response_throttled?
        super || content_for_scanner.match?(/^\s*too many requests\b/i)
      end
    end
  end
end
