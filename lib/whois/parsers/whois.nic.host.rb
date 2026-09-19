#--
# Ruby Whois
#++

require_relative 'base_icann_compliant'
require_relative 'registry_response_safety'

module Whois
  class Parsers
    # Parser for the Radix/Tucows WHOIS service used by .host.
    class WhoisNicHost < BaseIcannCompliant
      include RegistryResponseSafety

      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^>>> Domain \S+ is available for registration\s*$/,
      }

      property_supported :status do
        if available?
          :available
        elsif content_for_scanner.match?(/^Domain Name:\s*\S+/i)
          :registered
        else
          Whois::Parser.bug!(ParserError, "Unable to parse .host response status.")
        end
      end

      property_supported :registered? do
        status == :registered
      end

      def response_unavailable?
        super || content_for_scanner.match?(/^TLD is not supported\.?\s*$/i)
      end
    end
  end
end
