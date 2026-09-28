require_relative 'base_icann_compliant'

module Whois
  class Parsers
    # Parser for the PIR WHOIS service serving .GIVES.
    class WhoisNicGives < BaseIcannCompliant
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
          response = content_for_scanner
          missing = response.match?(/\A[ \t]*Domain not found\.[ \t]*(?:\r?\n|\z)/i)
          denial = response.match?(/^[ \t]*(?:[%#][ \t]*)?(?:access denied|permission denied|request denied|forbidden)\b/i)
          domains = response.scan(/^[ \t]*Domain Name:[ \t]*((?:[a-z0-9-]+\.)+gives)[ \t\r]*$/i).flatten.uniq
          has_registrar = response.match?(/^[ \t]*Registrar:[ \t]*\S/i)
          has_record_detail = response.match?(/^[ \t]*(?:Creation Date|Updated Date|Registry Expiry Date|Name Server):[ \t]*\S/i)
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
