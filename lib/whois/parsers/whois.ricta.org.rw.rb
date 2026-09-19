require_relative 'base_cocca2'

module Whois
  class Parsers
    # Parser for the RICTA WHOIS service used by .rw.
    class WhoisRictaOrgRw < BaseCocca2
      property_supported :status do
        if content_for_scanner.match?(/^The queried object does not exist: No Object Found\s*$/i)
          :available
        else
          super()
        end
      end
    end
  end
end
