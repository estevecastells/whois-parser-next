require_relative 'base_top1000_icann'

module Whois
  class Parsers
    class WhoisNicLove < BaseTop1000Icann
      AVAILABLE_DOMAIN_LINE = /^>>> Domain (?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+love is available for registration[ \t]*$/i
      RECORD_EVIDENCE = /^[ \t]*(?:Domain Name|Registry Domain ID|Creation Date|Registrar|Sponsoring Registrar|Domain Status|Name Server):[ \t]*\S/i

      property_supported :available? do
        available_marker_count == 1
      end

      def response_unavailable?
        body = content_for_scanner
        marker_count = available_marker_count

        super || (marker_count.positive? && (marker_count != 1 || body.match?(RECORD_EVIDENCE)))
      end

      private

      def available_marker_count
        content_for_scanner.lines.count { |line| line.match?(AVAILABLE_DOMAIN_LINE) }
      end
    end
  end
end
