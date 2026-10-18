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

    # Parser for the whois.ax server.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisAx < Base
      include RegistryResponseSafety

      property_supported :status do
        if contradictory_evidence?
          :unknown
        elsif available?
          :available
        elsif registered_evidence?
          :registered
        else
          :unknown
        end
      end

      property_supported :available? do
        !contradictory_evidence? && !!(content_for_scanner =~ /^No records matching \S+ found\.\s*$/i ||
           content_for_scanner =~ /^Domain not found\s*$/i)
      end

      property_supported :registered? do
        status == :registered
      end


      property_supported :created_on do
        if content_for_scanner =~ /Created:\s+(.+)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_not_supported :updated_on

      property_not_supported :expires_on


      property_supported :nameservers do
        content_for_scanner.scan(/Name Server \d:\s+(.+)\n/).flatten.map do |name|
          Parser::Nameserver.new(:name => name)
        end
      end

      private

      def contradictory_evidence?
        markers = content_for_scanner.scan(/^(?:No records matching \S+ found\.|Domain not found)[ \t]*$/i)
        markers.length > 1 || markers.any? && content_for_scanner.match?(/^(?:Domain Name:|domain\.+:|status\.+:|Created:|created\.+:|Name Server \d:)/i)
      end

      def registered_evidence?
        dotted = content_for_scanner.scan(/^domain\.+:[ \t]*(\S+)[ \t]*$/i).flatten
        if dotted.any?
          dotted.one? && dotted.first.match?(/\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+ax\z/i) &&
            content_for_scanner.scan(/^status\.+:[ \t]*(.+)$/i).flatten.map(&:strip) == ['Registered'] &&
            content_for_scanner.match?(/^created\.+:[ \t]*\d{2}\.\d{2}\.\d{4}[ \t]*$/i)
        else
          content_for_scanner.match?(/^Domain Name:\s+\S+/i) &&
            content_for_scanner.match?(/^(?:Created|Name Server \d):\s+\S+/i)
        end
      end

    end

  end
end
