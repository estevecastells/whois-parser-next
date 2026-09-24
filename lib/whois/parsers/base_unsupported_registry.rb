require_relative 'base'

module Whois
  class Parsers

    # Parser for a registry endpoint that is reachable but explicitly refuses
    # the requested TLD. It must never infer either availability or a
    # registration from that denial response.
    class BaseUnsupportedRegistry < Base
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
          /\A(?:TLD is not supported\.|No Data Found)[ \t]*(?:\n|\z)/i
        )
      end
    end

  end
end
