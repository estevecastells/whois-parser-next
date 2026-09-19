#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_cocca2'


module Whois
  class Parsers

    # Parser for the whois.nic.cd server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicCd < BaseCocca2

      property_supported :status do
        # Current CoCCA responses use Registry Domain ID. Older responses
        # used Domain ID, so keep both forms as registered evidence.
        if node("Registry Domain ID") || node("Domain ID")
          :registered
        elsif content_for_scanner.match?(/^Domain Status:\s*(?:Available|No Object Found)\s*$/i)
          :available
        else
          :unknown
        end
      end

    end

  end
end
