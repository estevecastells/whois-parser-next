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
    # = whois.nic.ir parser
    #
    # Parser for the whois.nic.ir server.
    #
    # NOTE: This parser is just a stub and provides only a few basic methods
    # to check for domain availability and get domain status.
    # Please consider to contribute implementing missing methods.
    # See WhoisNicIt parser for an explanation of all available methods
    # and examples.
    #
    class WhoisNicIr < Base
      include RegistryResponseSafety

      property_supported :status do
        if available?
          :available
        elsif content_for_scanner.match?(/^domain:\s*\S+/i)
          :registered
        else
          Whois::Parser.bug!(ParserError, "Unable to parse .ir response status.")
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /%ERROR:101: no entries found/)
      end

      property_supported :registered? do
        status == :registered
      end


      property_not_supported :created_on

      property_supported :updated_on do
        if content_for_scanner =~ /last-updated:\s+(.*)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_not_supported :expires_on


      property_supported :nameservers do
        content_for_scanner.scan(/nserver:\s+(.+)\n/).flatten.map do |name|
          Parser::Nameserver.new(:name => name)
        end
      end

    end

  end
end
