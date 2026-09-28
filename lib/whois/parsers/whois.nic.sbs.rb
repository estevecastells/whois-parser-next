require_relative 'base_identity_digital'
module Whois
  class Parsers
    class WhoisNicSbs < BaseIdentityDigital
      self.scanner = Scanners::BaseIcannCompliant, { pattern_available: /^The queried object does not exist: DOMAIN NOT FOUND\s*$/i }

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
          content_for_scanner.match?(/^The queried object does not exist: DOMAIN NOT FOUND\s*$/i)
      end
    end
  end
end
