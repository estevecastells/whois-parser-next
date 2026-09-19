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

    # Parser for the whois.nic.gl server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicGl < WhoisCentralnicCom
      property_supported :status do
        statuses = Array.wrap(node("Domain Status")).map do |value|
          value.to_s.split.first.to_s.downcase
        end

        return :available if available?
        return :registered if statuses.any?

        Whois::Parser.bug!(ParserError, "Unknown status `#{statuses.join(', ')}'.")
      end

      property_supported :available? do
        super() || content.match?(/^Domain Status:\s+No Object Found$/i)
      end

      property_supported :registrar do
        node("Sponsoring Registrar") do
          Parser::Registrar.new(
            id: node("Sponsoring Registrar IANA ID").presence,
            name: node("Sponsoring Registrar"),
            url: node("Sponsoring Registrar URL").presence
          )
        end
      end
    end

  end
end
