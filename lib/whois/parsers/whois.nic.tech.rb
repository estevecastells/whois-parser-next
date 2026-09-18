#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'whois.centralnic.com'


module Whois
  class Parsers

    # Parser for the whois.nic.tech server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicTech < WhoisCentralnicCom
      # The Radix registry uses the standard availability sentence rather
      # than the older CentralNic `DOMAIN NOT FOUND` response.
      property_supported :available? do
        super() || !!(content_for_scanner =~ /^>>> Domain .+ is available for registration/)
      end
    end

  end
end
