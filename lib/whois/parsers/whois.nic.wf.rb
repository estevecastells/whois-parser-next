#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_nic_fr'


module Whois
  class Parsers

    # Parser for the whois.nic.pm server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicWf < BaseNicFr
      # AFNIC uses this compact marker for a missing .wf object.
      property_supported :available? do
        !!(content_for_scanner =~ /^(?:%% NOT FOUND|%% No entries found in the AFNIC Database\.)\s*$/i)
      end
    end

  end
end
