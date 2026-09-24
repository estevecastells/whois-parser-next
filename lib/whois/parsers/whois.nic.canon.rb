require_relative 'base_unsupported_registry'

module Whois
  class Parsers
    class WhoisNicCanon < BaseUnsupportedRegistry
      def response_unavailable?
        super || content_for_scanner.match?(/\ANotice: .*WHOIS service has been retired/i)
      end
    end
  end
end
