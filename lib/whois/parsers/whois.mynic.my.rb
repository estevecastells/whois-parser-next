#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'


module Whois
  class Parsers

    # Parser for the whois.mynic.my server.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    class WhoisMynicMy < Base

      property_supported :status do
        if available?
          :available
        else
          :registered
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /Domain Name [^ ]+ does not exist in database/ ||
           content_for_scanner =~ /^>>> Domain .+ is available for registration$/)
      end

      property_supported :registered? do
        !available?
      end

      # MYNIC includes a normal informational "query limit is 500 per day"
      # footer in successful responses. Only classify explicit limit failures,
      # never that policy text, so a denied lookup cannot look registered.
      def response_throttled?
        content_for_scanner.match?(/^(?:\s*(?:%|#)\s*)?(?:whois\s+)?query\s+(?:rate\s+)?limit\s+exceeded\b/i) ||
          content_for_scanner.match?(/^(?:\s*(?:%|#)\s*)?you\s+have\s+exceeded\s+your\s+(?:daily|monthly)(?:\s+\w+){0,2}\s+(?:api\s+)?(?:rate\s+)?limit\b/i) ||
          content_for_scanner.match?(/^(?:\s*(?:%|#)\s*)?maximum\s+query\s+rate\s+reached\b/i)
      end

      def response_unavailable?
        content_for_scanner.match?(/^(?:\s*(?:%|#)\s*)?(?:requests of this client are not permitted|access to the whois service is denied)\b/i)
      end


      property_supported :created_on do
        if content_for_scanner =~ /\[Record Created\]\s+(.+?)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :updated_on do
        if content_for_scanner =~ /\[Record Last Modified\]\s+(.+?)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :expires_on do
        if content_for_scanner =~ /\[Record Expired\]\s+(.+?)\n/
          parse_time(::Regexp.last_match(1))
        end
      end


      property_supported :nameservers do
        content_for_scanner.scan(/\[(?:Primary|Secondary) Name Server\](?:.+?)\n(.+\n)/).flatten.map do |line|
          name, ipv4 = line.strip.split(/\s+/)
          Parser::Nameserver.new(:name => name, :ipv4 => ipv4)
        end
      end

    end

  end
end
