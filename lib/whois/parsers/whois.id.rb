#--
# Ruby Whois
#++

require_relative 'base_icann_compliant'

module Whois
  class Parsers

    # Parser for the current whois.id registry service.
    class WhoisId < BaseIcannCompliant

      self.scanner = Scanners::BaseIcannCompliant

      property_supported :available? do
        !!(content_for_scanner =~ /DOMAIN NOT FOUND/i)
      end

      property_supported :expires_on do
        node("Registry Expiry Date") { |value| parse_time(value) }
      end

    end

  end
end
