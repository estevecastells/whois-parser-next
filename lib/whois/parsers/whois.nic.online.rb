#--
# Ruby Whois
#++

require_relative 'base_icann_compliant'

module Whois
  class Parsers

    # Parser for the Radix WHOIS service used by .online.
    class WhoisNicOnline < BaseIcannCompliant

      self.scanner = Scanners::BaseIcannCompliant

      property_supported :available? do
        !!(content_for_scanner =~ /Domain .+ is available for registration/i)
      end

      property_supported :expires_on do
        node("Registry Expiry Date") { |value| parse_time(value) }
      end

    end

  end
end
