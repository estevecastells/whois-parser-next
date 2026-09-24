require_relative 'base_unsupported_registry'

module Whois
  class Parsers
    class WhoisDominioGq < BaseUnsupportedRegistry
      def response_unavailable?
        super || content_for_scanner.match?(/\AThe domain you requested is not known in Freenoms database\.\n\nThis TLD has no whois server\./i)
      end
    end
  end
end
