require_relative 'base_unsupported_registry'
require_relative 'registry_response_safety'

module Whois
  class Parsers
    # The registry retired port 43 WHOIS in favour of RDAP.
    class WhoisNicOkinawa < BaseUnsupportedRegistry
      include RegistryResponseSafety

      def response_unavailable?
        super || response_incomplete? || content_for_scanner.match?(
          /^Notice: Effective .* WHOIS service has been retired\b/i
        )
      end
    end
  end
end
