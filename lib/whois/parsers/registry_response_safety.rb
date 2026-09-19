module Whois
  class Parsers
    # Shared response classification for registries that use a plain-text
    # denial, throttling, or empty response instead of a WHOIS record.
    module RegistryResponseSafety
      def response_incomplete?
        content_for_scanner.strip.empty?
      end

      def response_throttled?
        content_for_scanner.match?(
          /^(?:\s*(?:%|#)\s*)?(?:whois\s+)?query\s+(?:rate\s+)?limit\s+exceeded\b/i
        ) || content_for_scanner.match?(
          /^(?:\s*(?:%|#)\s*)?maximum\s+query\s+rate\s+reached\b/i
        ) || content_for_scanner.match?(
          /^(?:\s*(?:%|#)\s*)?excessive\s+querying\b/i
        ) || content_for_scanner.match?(
          /^\s*(?:%|#)?\s*whois\s+limit\s+exceeded\b/i
        )
      end

      def response_unavailable?
        response_incomplete? || content_for_scanner.match?(
          /^(?:\s*(?:%|#)\s*)?(?:requests of this client are not permitted|access to the whois service is denied|whois service is unavailable)\b/i
        )
      end
    end
  end
end
