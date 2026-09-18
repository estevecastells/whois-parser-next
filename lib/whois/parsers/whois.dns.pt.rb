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

    # Parser for the whois.dns.pt server.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisDnsPt < Base

      property_supported :status do
        if content_for_scanner =~ %r{^(?:Estado / Status|Domain Status):\s+(.+)$}i
          case ::Regexp.last_match(1).downcase
          when "active", "registered"
            :registered
          when "reserved"
            :reserved
          when "tech-pro"
            :inactive
          else
            Whois::Parser.bug!(ParserError, "Unknown status `#{::Regexp.last_match(1)}'.")
          end
        else
          :available
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /^.* no match\s*$/i)
      end

      property_supported :registered? do
        !available?
      end


      property_supported :created_on do
        if content_for_scanner =~ / Creation Date .+?:\s+(.+)\n/
          parse_pt_date(::Regexp.last_match(1))
        elsif content_for_scanner =~ /^Creation Date:\s+(.+)$/i
          parse_pt_date(::Regexp.last_match(1))
        end
      end

      property_not_supported :updated_on

      property_supported :expires_on do
        if content_for_scanner =~ / Expiration Date .+?:\s+(.+)\n/
          parse_pt_date(::Regexp.last_match(1))
        elsif content_for_scanner =~ /^Expiration Date:\s+(.+)$/i
          parse_pt_date(::Regexp.last_match(1))
        end
      end


      property_supported :nameservers do
        names = content_for_scanner.scan(/^\s*Name Server:\s+([^\s|]+)/i).flatten
        names = content_for_scanner.scan(/Nameserver:\s+(?:.*)\s+NS\s+(.+?)\.\n/).flatten if names.empty?
        names.map do |name|
          Parser::Nameserver.new(:name => name)
        end
      end

      private

      def parse_pt_date(value)
        date, time = value.strip.split(/\s+/, 2)
        day, month, year = date.split("/").map(&:to_i)
        hour, minute, second = (time || "00:00:00").split(":").map(&:to_i)
        Time.utc(year, month, day, hour, minute, second)
      end

    end

  end
end
