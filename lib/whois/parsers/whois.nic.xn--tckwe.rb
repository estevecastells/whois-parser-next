require_relative 'whois.verisign-grs.com'
require_relative 'registry_response_safety'

module Whois
  class Parsers
    # The .コム endpoint exposes the VeriSign response shape, but this
    # adapter keeps unknown bodies out of the registered result.
    class WhoisNicXnTckwe < WhoisVerisignGrsCom
      include RegistryResponseSafety

      property_supported :status do
        if available?
          :available
        elsif content_for_scanner.match?(/^\s*Domain Name:\s*\S+/i)
          :registered
        else
          :unknown
        end
      end

      property_supported :registered? do
        status == :registered
      end

      def response_unavailable?
        super || response_incomplete?
      end
    end

    const_set('WhoisNicXn_tckwe', WhoisNicXnTckwe)
  end
end
