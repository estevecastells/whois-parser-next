require_relative 'base_icann_compliant'
require_relative 'registry_response_safety'

module Whois
  class Parsers
    # Parser for the Radix WHOIS service used by .store.
    class WhoisNicStore < BaseIcannCompliant
      include RegistryResponseSafety

      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^>>> Domain \S+ is available for registration\s*$/i,
      }

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
        !contradictory_registration_and_absence? && !!node('status:available')
      end

      property_supported :registered? do
        status == :registered
      end

      private

      def contradictory_registration_and_absence?
        !node('Domain Name').to_s.strip.empty? &&
          content_for_scanner.match?(/^>>> Domain \S+ is available for registration\s*$/i)
      end
    end
  end
end
