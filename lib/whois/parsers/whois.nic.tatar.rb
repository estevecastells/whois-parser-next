require_relative 'whois.nic.as'

module Whois
  class Parsers
    # The .tatar registry uses the ICANN key/value record layout and an
    # object-specific no-entry sentence.
    class WhoisNicTatar < WhoisNicAs
      property_supported :available? do
        super() || content_for_scanner.match?(/^The queried object does not exist:\s+\S+/i)
      end
    end
  end
end
