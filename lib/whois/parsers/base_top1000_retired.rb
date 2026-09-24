require_relative 'base'

module Whois
  class Parsers
    # WHOIS endpoints that have retired port-43 service in favour of RDAP.
    class BaseTop1000Retired < Base
      property_supported :status do
        :unknown
      end

      property_supported :available? do
        false
      end

      property_supported :registered? do
        false
      end

      def response_unavailable?
        content_for_scanner.match?(
          /^Notice: Effective May 1, 2026, the WHOIS service has been retired\b/i
        )
      end
    end
  end
end
