require_relative 'base_top1000_icann'

module Whois
  class Parsers
    # The .top registry uses the shared ICANN record shape and returns the full
    # queried .top name in its exact no-record response.
    class WhoisNicTop < BaseTop1000Icann
      property_supported :available? do
        super() || content_for_scanner.match?(
          /^The queried object does not exist:\s+(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.top\s*$/i
        )
      end
    end
  end
end
