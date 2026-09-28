#--
# Ruby Whois
#++

require_relative 'base_icann_compliant'

module Whois
  class Parsers

    # Parser for the Radix WHOIS service used by .online.
    class WhoisNicOnline < BaseIcannCompliant

      self.scanner = Scanners::BaseIcannCompliant

      property_supported :status do
        if contradictory_registration_and_absence?
          :unknown
        elsif available?
          :available
        elsif node('Domain Name').to_s.strip.empty? ||
              [node('Registry Domain ID'), node('Creation Date'), node('Registrar')].all? { |value| value.to_s.strip.empty? }
          :unknown
        else
          :registered
        end
      end

      property_supported :available? do
        !contradictory_registration_and_absence? && !!(content_for_scanner =~ /^>>> Domain \S+ is available for registration\s*$/i)
      end

      property_supported :registered? do
        status == :registered
      end

      # Radix can answer with a limit or client-denial notice that contains no
      # domain evidence. Do not let Base#registered? turn those responses into
      # false registrations.
      def response_throttled?
        super || content_for_scanner.match?(/^(?:\s*(?:%|#)\s*)?(?:whois\s+)?query\s+(?:rate\s+)?limit\s+exceeded\b/i) ||
          content_for_scanner.match?(/^(?:\s*(?:%|#)\s*)?maximum\s+query\s+rate\s+reached\b/i) ||
          content_for_scanner.match?(/^(?:\s*(?:%|#)\s*)?excessive\s+querying\b/i)
      end

      def response_unavailable?
        super || content_for_scanner.match?(/^(?:\s*(?:%|#)\s*)?(?:requests of this client are not permitted|access to the whois service is denied)\b/i)
      end

      property_supported :expires_on do
        node("Registry Expiry Date") { |value| parse_time(value) }
      end

      private

      def contradictory_registration_and_absence?
        !node('Domain Name').to_s.strip.empty? &&
          content_for_scanner.match?(/^>>> Domain \S+ is available for registration\s*$/i)
      end

    end

  end
end
