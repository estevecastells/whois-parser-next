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
    # = whois.nic.ci parser
    #
    # Parser for the whois.nic.ci server.
    #
    # NOTE: This parser is just a stub and provides only a few basic methods
    # to check for domain availability and get domain status.
    # Please consider to contribute implementing missing methods.
    # See WhoisNicIt parser for an explanation of all available methods
    # and examples.
    #
    class WhoisNicCi < Base
      include RegistryResponseSafety

      property_supported :status do
        if available?
          :available
        elsif content_for_scanner.match?(/^Domain:\s*\S+/i) && content_for_scanner.match?(/^Created:\s*\S+/i)
          :registered
        else
          :unknown
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /^Domain \S+ not found\s*$/i)
      end

      property_supported :registered? do
        status == :registered
      end


      property_supported :created_on do
        if content_for_scanner =~ /Created: (.+?)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_not_supported :updated_on

      property_supported :expires_on do
        if content_for_scanner =~ /Expiration date: (.+?)\n/
          parse_time(::Regexp.last_match(1))
        end
      end


      property_supported :nameservers do
        content_for_scanner.scan(/Nameserver:\s+(.+)\n/).flatten.map do |name|
          Parser::Nameserver.new(:name => name)
        end
      end

    end

  end
end
