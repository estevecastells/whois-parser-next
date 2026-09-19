#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require_relative 'base_cocca'
require_relative 'registry_response_safety'


module Whois
  class Parsers

    # Parser for the whois.nic.ec server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicEc < BaseCocca
      include RegistryResponseSafety

      property_supported :status do
        if content_for_scanner =~ /Status:\s+(.+?)\n/
          super()
        elsif content_for_scanner.match?(/^The queried object does not exist:\s*No Object Found\s*$/i)
          :available
        elsif registrar
          :registered
        else
          Whois::Parser.bug!(ParserError, "Unable to parse .ec response status.")
        end
      end

      property_supported :registered? do
        status == :registered
      end
    end

  end
end
