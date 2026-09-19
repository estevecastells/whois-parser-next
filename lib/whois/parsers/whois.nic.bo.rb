#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require_relative 'registry_response_safety'


module Whois
  class Parsers

    # Parser for the whois.nic.bo server.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicBo < Base
      include RegistryResponseSafety

      property_supported :domain do
        if content_for_scanner =~ /Dominio:(.*)\n/
          ::Regexp.last_match(1).strip
        end
      end

      property_not_supported :domain_id


      property_supported :status do
        if domain
          :registered
        else
          Whois::Parser.bug!(ParserError, "Unable to parse .bo response status.")
        end
      end

      property_supported :available? do
        status == :available
      end

      property_supported :registered? do
        status == :registered
      end

      def response_unavailable?
        super || (
          content_for_scanner.match?(/^whois\.nic\.bo solo acepta consultas con dominios \.bo\s*$/i) &&
            !content_for_scanner.match?(/^Dominio:\s*\S+/i)
        )
      end


      property_supported :created_on do
        if content_for_scanner =~ /Fecha de registro:(.*)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_not_supported :updated_on

      property_supported :expires_on do
        if content_for_scanner =~ /Fecha de vencimiento:(.*)\n/
          parse_time(::Regexp.last_match(1))
        end
      end


      property_not_supported :nameservers

    end

  end
end
