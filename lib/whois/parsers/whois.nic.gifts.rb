require_relative 'base_unsupported_registry'

module Whois
  class Parsers
    # Identity Digital's shared endpoint explicitly reports that .GIFTS is
    # unsupported over WHOIS. The TLD's authoritative registry data is RDAP.
    class WhoisNicGifts < BaseUnsupportedRegistry
      def response_unavailable?
        content_for_scanner.match?(/\A[ \t]*TLD is not supported\.[ \t]*(?:\r?\n|\z)/i)
      end
    end
  end
end
