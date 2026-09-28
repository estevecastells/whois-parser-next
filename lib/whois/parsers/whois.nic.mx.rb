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
    # = whois.nic.mx parser
    #
    # Parser for the whois.nic.mx server.
    #
    # NOTE: This parser is just a stub and provides only a few basic methods
    # to check for domain availability and get domain status.
    # Please consider to contribute implementing missing methods.
    # See WhoisNicIt parser for an explanation of all available methods
    # and examples.
    #
    class WhoisNicMx < Base
      include RegistryResponseSafety

      DOMAIN_PATTERN = /\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+mx\z/i
      NO_RECORD_MARKER = %r{^[ \t]*No_Se_Encontro_El_Objeto/Object_Not_Found[ \t]*$}i
      RECORD_EVIDENCE = /^[ \t]*(?:Created On|Expiration Date|Registrar|Name Servers|DNS):/i

      property_supported :status do
        classify_status
      end

      property_supported :available? do
        classify_status == :available
      end

      property_supported :registered? do
        classify_status == :registered
      end


      property_supported :created_on do
        if content_for_scanner =~ /Created On:\s+(.*)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      # FIXME: the response contains localized data
      # Expiration Date: 10-may-2011
      # Last Updated On: 15-abr-2010 <--
      # property_supported :updated_on do
      #   if content_for_scanner =~ /Last Updated On:\s+(.*)\n/
      #     parse_time($1)
      #   end
      # end

      property_supported :expires_on do
        if content_for_scanner =~ /Expiration Date:\s+(.*)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :nameservers do
        if content_for_scanner =~ /Name Servers:\n((.+\n)+)\n/
          ::Regexp.last_match(1).scan(/DNS:\s+(.+)\n/).flatten.map do |line|
            name, ipv4 = line.strip.split(/\s+/)
            Parser::Nameserver.new(:name => name, :ipv4 => ipv4)
          end
        end
      end

      def response_unavailable?
        super || content_for_scanner.match?(
          /^\s*(?:access denied|permission denied|request denied|forbidden)\b/i
        )
      end

      private

      def classify_status
        cached_properties_fetch(:classified_status) do
          response = content_for_scanner
          absent = response.lines.one? { |line| line.match?(NO_RECORD_MARKER) }
          domain_rows = response.scan(/^[ \t]*Domain Name:[ \t]*(.*?)[ \t\r]*$/i).flatten
          domains = domain_rows.grep(DOMAIN_PATTERN)
          has_created = response.match?(/^[ \t]*Created On:[ \t]*\S/i)
          has_expires = response.match?(/^[ \t]*Expiration Date:[ \t]*\S/i)
          has_registrar = response.match?(/^[ \t]*Registrar:[ \t]*\S/i)
          registered = [
            domain_rows.one?,
            domains.one?,
            has_created,
            has_expires,
            has_registrar,
            !response_unavailable?,
            !response_throttled?,
          ].all?
          has_record_evidence = response.match?(RECORD_EVIDENCE)

          if absent && domain_rows.empty? && !has_record_evidence && !response_unavailable? && !response_throttled?
            :available
          elsif registered && !absent
            :registered
          else
            :unknown
          end
        end
      end

    end

  end
end
