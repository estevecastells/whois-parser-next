require_relative 'base'

module Whois
  class Parsers
    # A registry response that explicitly reserves or prohibits the queried
    # name. It is not evidence of either registration or availability.
    class BaseReservedRegistry < Base
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
          /\A(?:Reserved Domain Name|This name is reserved by the Registry\b|The queried object does not exist:.*reserved list)/i
        )
      end
    end
  end
end
