require_relative 'base_icann_compliant'
require_relative 'registry_response_safety'

module Whois
  class Parsers
    class WhoisNicGiving < BaseIcannCompliant
      include RegistryResponseSafety

      DOMAIN_PATTERN = /\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+giving\z/i
      NO_RECORD_MARKER = /^[ \t]*Domain not found\.[ \t]*$/i

      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: NO_RECORD_MARKER,
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
          missing = response.lines.one? { |line| line.match?(NO_RECORD_MARKER) }
          denial = response.match?(/^[ \t]*(?:[%#][ \t]*)?(?:access denied|permission denied|request denied|forbidden)\b/i)
          domain_lines = response.scan(/^[ \t]*Domain Name:[ \t]*(.*?)[ \t\r]*$/i).flatten
          domains = domain_lines.grep(DOMAIN_PATTERN)
          has_registrar = response.match?(/^[ \t]*Registrar:[ \t]*\S/i)
          has_record_detail = response.match?(/^[ \t]*(?:Creation Date|Updated Date|Registry Expiry Date|Name Server):[ \t]*\S/i)
          has_record = domain_lines.one? && domains.one? && has_registrar && has_record_detail

          if missing && domain_lines.empty? && !denial && !response_unavailable? && !response_throttled?
            :available
          elsif has_record && !missing && !denial && !response_unavailable? && !response_throttled?
            :registered
          else
            :unknown
          end
        end
      end
    end
  end
end
