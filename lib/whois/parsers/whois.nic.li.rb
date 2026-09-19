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

    #
    # = whois.nic.li parser
    #
    # Parser for the whois.nic.li server.
    #
    # NOTE: This parser is just a stub and provides only a few basic methods
    # to check for domain availability and get domain status.
    # Please consider to contribute implementing missing methods.
    # See WhoisNicIt parser for an explanation of all available methods
    # and examples.
    #
    class WhoisNicLi < Base
      include RegistryResponseSafety

      property_supported :status do
        if available?
          :available
        elsif content_for_scanner.match?(/^Domain name:\s*\S+/i)
          :registered
        else
          Whois::Parser.bug!(ParserError, "Unable to parse .li response status.")
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /We do not have an entry in our database matching your query\./)
      end

      property_supported :registered? do
        status == :registered
      end


      property_not_supported :created_on

      property_not_supported :updated_on

      property_not_supported :expires_on


      property_supported :nameservers do
        if content_for_scanner =~ /Name servers:\n((.+\n)+)(?:\n|\z)/
          ::Regexp.last_match(1).split("\n").map do |name|
            Parser::Nameserver.new(:name => name)
          end
        end
      end

    end

  end
end
