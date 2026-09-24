require_relative 'base'
require_relative 'registry_response_safety'

module Whois
  class Parsers
    # Parser for the Aruba registry's compact port-43 response.
    class WhoisNicAw < Base
      include RegistryResponseSafety

      property_supported :domain do
        content_for_scanner[/^Domain name:\s*(\S+)/i, 1]&.downcase
      end

      property_supported :status do
        if available?
          :available
        elsif content_for_scanner.match?(/^Status:\s*active\s*$/i)
          :registered
        else
          :unknown
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /^\S+\s+is free\s*$/i)
      end

      property_supported :registered? do
        status == :registered
      end
    end
  end
end
