#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_cocca2'
require_relative 'cocca_epp_status'


module Whois
  class Parsers

    # Parser for the whois1.nic.bi server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class Whois1NicBi < BaseCocca2
      include CoccaEppStatus

      CURRENT_COCCA_SUFFIX = "bi".freeze

      property_supported :status do
        current_cocca_status || super()
      end

      property_supported :available? do
        status == :available
      end

      property_supported :registered? do
        status == :registered
      end
    end

  end
end
