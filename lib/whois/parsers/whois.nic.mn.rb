#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#++

require_relative 'base_icann_compliant'

module Whois
  class Parsers
    # Parser for the IANA-listed .mn WHOIS host, whois.nic.mn.
    class WhoisNicMn < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^[ \t]*Domain not found\.[ \t\r]*$/i,
      }

      property_supported :status do
        classify_status
      end

      property_supported :available? do
        classify_status == :available
      end

      property_supported :registered? do
        classify_status == :registered
      end

      private

      def classify_status
        cached_properties_fetch(:classified_status) do
          missing = content_for_scanner.match?(/\A[ \t]*Domain not found\.[ \t\r]*(?:\n|\z)/i)
          denial = content_for_scanner.match?(/^[ \t]*(?:[%#][ \t]*)?(?:access denied|permission denied|request denied|forbidden)\b/i)
          domains = content_for_scanner.scan(/^[ \t]*Domain Name:[ \t]*((?:[a-z0-9-]+\.)+mn)[ \t\r]*$/i).flatten.uniq
          has_registrar = content_for_scanner.match?(/^[ \t]*Registrar:[ \t]*\S/i)
          has_record_detail = content_for_scanner.match?(/^[ \t]*(?:Creation Date|Updated Date|Registry Expiry Date|Name Server):[ \t]*\S/i)
          has_record = domains.one? && has_registrar && has_record_detail

          if missing && domains.empty? && !denial && !response_throttled?
            :available
          elsif has_record && !missing && !denial && !response_throttled?
            :registered
          else
            :unknown
          end
        end
      end
    end
  end
end
