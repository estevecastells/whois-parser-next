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

      property_supported :domain do
        content_for_scanner[/^[ \t]*Domain Name:[ \t]*(\S+)[ \t]*\r?$/i, 1]&.downcase
      end

      property_supported :status do
        body = content_for_scanner
        names = body.scan(/^[ \t]*Domain Name:[ \t]*(\S+)[ \t]*\r?$/i).flatten
        missing = body.scan(/^(?:No match for "([^"\r\n]+)"\.|The queried object does not exist: ([^\r\n]+)\.)[ \t]*\r?$/i).map { |parts| parts.compact.first }
        dates = body.scan(/^[ \t]*(?:Creation Date|Domain Created):[ \t]*([^\r\n]+)$/i).flatten
        if missing.any?
          missing.one? && names.empty? && dates.empty? && valid_ws_domain?(missing.first) ? :available : :unknown
        else
          times = dates.map { |date| begin parse_time(date.strip); rescue ArgumentError; nil; end }
          names.one? && valid_ws_domain?(names.first) && times.any? && times.none?(&:nil?) && times.uniq.one? ? :registered : :unknown
        end
      end

      property_supported :available? do
        status == :available
      end

      property_supported :registered? do
        status == :registered
      end


      property_supported :created_on do
        value = content_for_scanner[/^[ \t]*(?:Creation Date|Domain Created):[ \t]*([^\r\n]+)$/i, 1]
        parse_time(value.strip) if value
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

      private

      def valid_ws_domain?(name)
        name.match?(/\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+ws\z/i)
      end

    end

  end
end
