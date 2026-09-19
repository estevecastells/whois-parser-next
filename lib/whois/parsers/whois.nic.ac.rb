#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_icb'


module Whois
  class Parsers

    # Parser for the whois.nic.ac server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicAc < BaseIcb

      # The registry currently uses the same absence wording as Identity
      # Digital's other WHOIS services, in addition to the older `NOT FOUND`
      # response handled by BaseIcb.
      self.scanner = Scanners::BaseIcannCompliant, {
          pattern_available: /^(?:NOT FOUND|Domain not found\.)/i,
      }

    end

  end
end
