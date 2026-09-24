require_relative 'base'
require_relative 'registry_response_safety'

module Whois
  class Parsers
    # The .укр registry uses an exact "No match for domain" response.
    class WhoisDotukrCom < Base
      include RegistryResponseSafety

      property_supported :status do
        available? ? :available : :unknown
      end

      property_supported :available? do
        !!(content_for_scanner =~ /^No match for domain\s+\S+\.?\s*$/i)
      end

      property_supported :registered? do
        false
      end
    end
  end
end
