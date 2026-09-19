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

    # Parser for the whois.nic.design server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicDesign < WhoisCentralnicCom
      # The current CentralNic service emits `No Data Found` without a
      # domain header for a generated absence query.
      property_supported :available? do
        super() || content_for_scanner.match?(/^No Data Found\s*$/i)
      end
    end

  end
end
