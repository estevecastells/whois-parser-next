#--
# Ruby Whois
#++

require_relative 'base'
require_relative 'registry_response_safety'

module Whois
  class Parsers

    # Parser for PKNIC's port-43 service.
    #
    # PKNIC identifies positive registration and availability results with
    # separate status lines. Keep other responses unknown rather than
    # inferring absence from an incomplete "Not Registered" message.
    class WhoisPknicNetPk < Base
      include RegistryResponseSafety

      property_supported :domain do
        echoed_domain
      end

      property_supported :status do
        registered = registered_evidence?
        available = available_evidence?

        if registered && !available
          :registered
        elsif available && !registered
          :available
        else
          :unknown
        end
      end

      property_supported :available? do
        available_evidence? && !registered_evidence?
      end

      property_supported :registered? do
        registered_evidence? && !available_evidence?
      end

      property_not_supported :created_on
      property_not_supported :updated_on
      property_not_supported :expires_on
      property_not_supported :registrant_contacts
      property_not_supported :admin_contacts
      property_not_supported :technical_contacts
      property_not_supported :nameservers

      private

      def echoed_domain
        content_for_scanner[/^ {0,8}Domain:[ \t]*((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+pk)[ \t]*$/i, 1]
      end

      def registered_evidence?
        !!(echoed_domain && content_for_scanner.match?(/^ {0,8}Status: Domain is Registered[ \t]*$/))
      end

      def available_evidence?
        !!(echoed_domain &&
          content_for_scanner.match?(/^ {0,8}Status: Not Registered, and may be available if valid[ \t]*$/) &&
          content_for_scanner.match?(/^ {0,8}Available: Yes\.[ \t]*$/))
      end
    end

  end
end
