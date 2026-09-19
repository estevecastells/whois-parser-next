#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#++

require_relative 'base_whoisd'

module Whois
  class Parsers

    # Parser for the whois.nic.mw server.
    #
    # Malawi's current service emits a whoisd-style record without a status
    # field. Presence of the domain key is the registered signal; the
    # standard `%ERROR:101: no entries found` marker is handled by the base
    # scanner for availability.
    class WhoisNicMw < BaseWhoisd

      property_supported :status do
        if available?
          :available
        elsif node('domain') && [node('registered'), node('registrar'), node('expire')].any?(&:present?)
          :registered
        else
          :unknown
        end
      end

    end

  end
end
