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
    # = whois.nic.coop parser
    #
    # Parser for the whois.nic.coop server.
    #
    # NOTE: This parser is just a stub and provides only a few basic methods
    # to check for domain availability and get domain status.
    # Please consider to contribute implementing missing methods.
    # See WhoisNicIt parser for an explanation of all available methods
    # and examples.
    #
    class WhoisNicCoop < Base
      include RegistryResponseSafety

      property_supported :status do
        statuses = content_for_scanner.scan(/Status:\s+(.+?)\n/).flatten
        if statuses.empty? && !available?
          :unknown
        else
          statuses
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /^No domain records were found to match\s+"[^"]+"\s*$/i ||
           content_for_scanner =~ /^>>> Domain \S+ is available for registration\s*$/i)
      end

      property_supported :registered? do
        !available? && registered_evidence?
      end


      property_supported :created_on do
        if content_for_scanner =~ /Created:\s+(.*)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :updated_on do
        if content_for_scanner =~ /Last updated:\s+(.*)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :expires_on do
        if content_for_scanner =~ /Expiry Date:\s+(.*)\n/
          parse_time(::Regexp.last_match(1))
        end
      end


      property_supported :nameservers do
        content_for_scanner.scan(/Host Name:\s+(.+)\n/).flatten.map do |name|
          Parser::Nameserver.new(:name => name)
        end
      end

      private

      def registered_evidence?
        content_for_scanner.match?(/^Domain Name:\s+\S+/i) &&
          content_for_scanner.match?(/^(?:Domain ID|Created):\s+\S+/i)
      end

    end

  end
end
