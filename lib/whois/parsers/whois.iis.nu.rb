#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require_relative 'base_iisse'
require_relative 'registry_response_safety'


module Whois
  class Parsers

    # Parser for the whois.iis.nu server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisIisNu < BaseIisse
      include RegistryResponseSafety

      property_supported :status do
        if content_for_scanner.match?(/^domain\s+"[^"]+"\s+not found\./i)
          :available
        elsif content_for_scanner.match?(/^state:\s+/i)
          :registered
        else
          Whois::Parser.bug!(ParserError, "Unable to parse .nu response status.")
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /^domain\s+"[^"]+"\s+not found\./i)
      end

      property_supported :registered? do
        status == :registered
      end
    end

  end
end
