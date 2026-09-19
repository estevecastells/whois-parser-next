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

    # Parser for the whois.nic.tl server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicTl < BaseCocca2
      property_supported :status do
        if content_for_scanner.match?(/^The queried object does not exist: No Object Found\s*$/i)
          :available
        else
          super()
        end
      end
    end

  end
end
