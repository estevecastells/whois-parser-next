require_relative 'base_nic_fr'

module Whois
  class Parsers
    # AFNIC-format parser for the .yt registry.
    class WhoisNicYt < BaseNicFr
      property_supported :available? do
        content_for_scanner.match?(/^%% NOT FOUND\s*$/i)
      end

      property_supported :created_on do
        parse_time(content_for_scanner[/^created:\s+(.+)\s*$/i, 1])
      end

      property_supported :updated_on do
        parse_time(content_for_scanner[/^last-update:\s+(.+)\s*$/i, 1])
      end

      property_supported :expires_on do
        parse_time(content_for_scanner[/^Expiry Date:\s+(.+)\s*$/i, 1])
      end
    end
  end
end
