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

    # Parser for the whois.website.ws server.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisWebsiteWs < Base
      include RegistryResponseSafety

      property_supported :status do
        if available?
          :available
        elsif content_for_scanner.match?(/^\s+Domain Created:\s+/i)
          :registered
        else
          :unknown
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /^No match for "\S+"\.$/ ||
           content_for_scanner =~ /^The queried object does not exist: \S+\.$/)
      end

      property_supported :registered? do
        status == :registered
      end


      property_supported :created_on do
        if content_for_scanner =~ /\s+Domain Created:\s+(.*)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :updated_on do
        if content_for_scanner =~ /\s+Domain Last Updated:\s+(.*)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :expires_on do
        if content_for_scanner =~ /\s+Domain Currently Expires:\s+(.*)\n/
          parse_time(::Regexp.last_match(1))
        end
      end


      property_supported :nameservers do
        if content_for_scanner =~ /Current Nameservers:\n\n((.+\n)+)\n/
          ::Regexp.last_match(1).split("\n").map do |name|
            Parser::Nameserver.new(name: name.strip.downcase)
          end
        end
      end

    end

  end
end
