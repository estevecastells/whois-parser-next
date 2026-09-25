#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_cocca2'
require_relative 'registry_response_safety'


module Whois
  class Parsers

    # Parser for the whois.nic.hn server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicHn < BaseCocca2
      include RegistryResponseSafety

      property_supported :status do
        if no_object_found?
          registration_fields_present? ? :unknown : :available
        else
          super()
        end
      end

      property_supported :available? do
        status == :available
      end

      property_supported :registered? do
        status == :registered
      end

      private

      def no_object_found?
        content_for_scanner.match?(/^The queried object does not exist:\s*No Object Found\s*$/i)
      end

      def registration_fields_present?
        content_for_scanner.match?(
          /^[ \t]*(?:Domain Status|Domain ID|Creation Date|Updated Date|Registry Expiry Date|Name Server|(?:Sponsoring )?Registrar|Registrant|Admin|Billing|Tech):/i
        )
      end
    end

  end
end
