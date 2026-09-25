require_relative 'base_icann_compliant'

module Whois
  class Parsers
    # Parser for IANA's current .africa WHOIS endpoint, whois.nic.africa.
    #
    # The registry's exact `No information was found matching that query.`
    # response is treated as absence. Other unrecognised responses remain
    # unknown, and inherited response-safety checks preserve denials and
    # throttling as errors.
    class WhoisNicAfrica < BaseIcannCompliant
      property_supported :available? do
        content_for_scanner.match?(
          /^[ \t]*No information was found matching that query\.[ \t]*$/i
        )
      end

      property_supported :expires_on do
        node("Registry Expiry Date") { |value| parse_time(value) }
      end
    end
  end
end
