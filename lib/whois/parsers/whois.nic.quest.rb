require_relative 'whois.centralnic.com'

module Whois
  class Parsers
    class WhoisNicQuest < WhoisCentralnicCom
      property_supported :available? do
        !contradictory_registration_and_absence? && !!node('status:available')
      end

      property_supported :registered? do
        !contradictory_registration_and_absence? &&
          !available? && !Array.wrap(node('Status') || node('Domain Status')).empty? &&
          !node('Domain Name').to_s.strip.empty? &&
          Array.wrap(node('Status') || node('Domain Status')).none? { |value| value.to_s.strip.casecmp('unknown').zero? }
      end

      private

      def contradictory_registration_and_absence?
        !node('Domain Name').to_s.strip.empty? &&
          content_for_scanner.match?(/^(?:DOMAIN NOT FOUND|The queried object does not exist: DOMAIN NOT FOUND|>>> Domain \S+ is available for registration)\s*$/i)
      end
    end
  end
end
