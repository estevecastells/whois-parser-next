require_relative 'whois.cira.ca'
require_relative 'registry_response_safety'

module Whois
  class Parsers
    # The .blog registry uses the CIRA response layout and an exact
    # `Not found:` absence marker.
    class WhoisNicBlog < WhoisCiraCa
      include RegistryResponseSafety

      property_supported :status do
        if content_for_scanner.match?(/^Not found:\s+/i)
          :available
        elsif content_for_scanner.match?(/^Domain Status:\s+\S+/i)
          :registered
        else
          :unknown
        end
      end

      property_supported :available? do
        status == :available
      end

      property_supported :registered? do
        status == :registered
      end

      def response_unavailable?
        super || content_for_scanner.match?(/^Error code:\s*\S+/i)
      end
    end
  end
end
