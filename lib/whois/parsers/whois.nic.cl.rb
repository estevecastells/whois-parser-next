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

    #
    # = whois.nic.cl parser
    #
    # Parser for the whois.nic.cl server.
    #
    # NOTE: This parser is just a stub and provides only a few basic methods
    # to check for domain availability and get domain status.
    # Please consider to contribute implementing missing methods.
    # See WhoisNicIt parser for an explanation of all available methods
    # and examples.
    #
    class WhoisNicCl < Base

      property_supported :status do
        classify_status
      end

      property_supported :available? do
        classify_status == :available
      end

      property_supported :registered? do
        classify_status == :registered
      end


      property_not_supported :created_on

      # TODO: custom date format with foreign month names
      # property_supported :updated_on do
      #   if content_for_scanner =~ /changed:\s+(.*)\n/
      #     parse_time($1.split(" ", 2).last)
      #   end
      # end

      property_not_supported :expires_on


      property_supported :nameservers do
        if content_for_scanner =~ /Servidores de nombre \(Domain servers\):\n((.+\n)+)\n/
          ::Regexp.last_match(1).split("\n").map do |line|
            line.strip!
            line =~ /(.+) \((.+)\)/
            Parser::Nameserver.new(:name => ::Regexp.last_match(1), :ipv4 => ::Regexp.last_match(2))
          end
        else
          content_for_scanner.scan(/^Name server:\s+(.+)$/i).flatten.map do |name|
            Parser::Nameserver.new(name: name.strip)
          end
        end
      end

      private

      # The current response layout in the DomScan corpus does not echo the
      # queried domain. This parser can require a record-shaped response, but
      # cannot independently verify that the returned record matches the query.
      def classify_status
        cached_properties_fetch(:classified_status) do
          available = content_for_scanner.match?(/^(?:[a-z0-9-]+\.)+cl:[ \t]*(?:no existe|no entries found\.)[ \t]*$/i)
          current_record = content_for_scanner.match?(/^Registrar name:[ \t]*\S[^\r\n]*$/i) &&
                           content_for_scanner.match?(/^Creation date:[ \t]*\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])(?:[ \t]+\d{2}:\d{2}:\d{2}[ \t]+[A-Z]{2,5})?[ \t]*$/i) &&
                           content_for_scanner.match?(/^Expiration date:[ \t]*\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])(?:[ \t]+\d{2}:\d{2}:\d{2}[ \t]+[A-Z]{2,5})?[ \t]*$/i) &&
                           content_for_scanner.match?(/^Name server:[ \t]*(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?[ \t]*$/i)
          legacy_record = content_for_scanner.match?(/^ACE:[ \t]*(?:[a-z0-9-]+\.)+cl[ \t]+\(RFC-3490, RFC-3491, RFC-3492\)/i) &&
                          content_for_scanner.match?(/^Servidores de nombre \(Domain servers\):/i)
          record = current_record || legacy_record
          record_marker = content_for_scanner.match?(/^(?:Registrant(?: name| organisation| organization| email| address)?|Registrar(?: name| URL)?|Creation date|Expiration date|Name server|ACE):/i) ||
                          content_for_scanner.match?(/^Servidores de nombre \(Domain servers\):/i)
          denied = content_for_scanner.match?(/\b(?:not\s+authori[sz]ed|unauthori[sz]ed|access\s+denied|permission\s+denied|too\s+many\s+requests|rate[- ]?limited?)\b|\bno\s+autorizad[oa]\b|\bacceso\s+denegado\b/i)

          if !denied && available && !record_marker
            :available
          elsif !denied && record && !available
            :registered
          else
            :unknown
          end
        end
      end

    end

  end
end
