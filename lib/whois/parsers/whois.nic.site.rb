#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#++


require_relative 'base'
require_relative 'registry_response_safety'


module Whois
  class Parsers

    # Parser for the whois.nic.site server.
    class WhoisNicSite < Base
      include RegistryResponseSafety

      property_supported :domain do
        content_for_scanner[/^Domain Name:\s*(\S+)/, 1]&.downcase
      end

      property_supported :status do
        if available?
          :available
        elsif reserved?
          :reserved
        elsif content_for_scanner.match?(/^Domain Name:\s*\S+/i)
          :registered
        else
          :unknown
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /^>>> Domain \S+ is available for registration$/)
      end

      property_supported :registered? do
        [:registered, :reserved].include?(status)
      end

      # A rate-limit or client-denial response has no domain record. Keep it
      # out of the parser's registered fallback.
      def response_throttled?
        super || content_for_scanner.match?(/^(?:\s*(?:%|#)\s*)?(?:whois\s+)?query\s+(?:rate\s+)?limit\s+exceeded\b/i) ||
          content_for_scanner.match?(/^(?:\s*(?:%|#)\s*)?maximum\s+query\s+rate\s+reached\b/i) ||
          content_for_scanner.match?(/^(?:\s*(?:%|#)\s*)?excessive\s+querying\b/i)
      end

      def response_unavailable?
        super || content_for_scanner.match?(/^(?:\s*(?:%|#)\s*)?(?:requests of this client are not permitted|access to the whois service is denied)\b/i)
      end

      def reserved?
        !!(content_for_scanner =~ /^>>> Domain name is (?:registry )?(?:reserved|blocked)$/)
      end

    end

  end
end
