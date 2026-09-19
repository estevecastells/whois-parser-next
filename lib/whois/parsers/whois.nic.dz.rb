#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require_relative 'registry_response_safety'


module Whois
  class Parsers

    #
    # = whois.nic.dz parser
    #
    # Parser for the whois.nic.dz server.
    #
    # The registry returns a compact, non-key/value response. Keep the
    # classifier deliberately narrow so transport errors and unrelated prose
    # cannot be mistaken for an available domain.
    #
    class WhoisNicDz < Base
      include RegistryResponseSafety

      property_supported :domain do
        content_for_scanner[/^Domain Name:\s*(\S+)/i, 1]&.downcase
      end

      property_supported :status do
        if available?
          :available
        elsif registered?
          :registered
        else
          :unknown
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /^%\s*No match for domain\s+'[^']+'\.\s*$/i ||
          content_for_scanner =~ /^NO OBJECT FOUND!\s*$/i)
      end

      property_supported :registered? do
        !available? &&
          ((content_for_scanner.match?(/^Domain Name:\s*\S+/i) && content_for_scanner.match?(/^Registrar:\s*\S+/i)) ||
            (content_for_scanner.match?(/^Nom de domaine#.*\S/i) && content_for_scanner.match?(/^Registrar#.*\S/i)))
      end


      property_not_supported :created_on

      property_not_supported :updated_on

      property_not_supported :expires_on


      property_not_supported :nameservers

    end

  end
end
