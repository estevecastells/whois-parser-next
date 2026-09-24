require_relative 'base_icann_compliant'

module Whois
  class Parsers
    # The .bzh registry uses the ICANN key/value record layout and AFNIC's
    # compact `%% NOT FOUND` absence marker.
    class WhoisNicBzh < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^%% NOT FOUND\s*$/i,
      }

      property_supported :status do
        if content_for_scanner.match?(/^%% NOT FOUND\s*$/i)
          :available
        elsif content_for_scanner.match?(/^Domain Name:\s+\S+/i) &&
              content_for_scanner.match?(/^Domain Status:\s+\S+/i)
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
    end
  end
end
