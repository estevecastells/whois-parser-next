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
    # = whois.isoc.org.il parser
    #
    # Parser for the whois.isoc.org.il server.
    #
    # NOTE: This parser is just a stub and provides only a few basic methods
    # to check for domain availability and get domain status.
    # Please consider to contribute implementing missing methods.
    # See WhoisNicIt parser for an explanation of all available methods
    # and examples.
    #
    class WhoisIsocOrgIl < Base
      include RegistryResponseSafety

      property_supported :status do
        names = content_for_scanner.scan(/^domain:[ \t]*(.+)$/i).flatten.map(&:strip)
        states = content_for_scanner.scan(/^status:[ \t]*(.+)$/i).flatten.map { |value| value.strip.downcase }
        missing = content_for_scanner.scan(/^% No data was found to match the request criteria\.[ \t]*$/).size
        if missing == 1 && names.empty? && states.empty?
          :available
        elsif missing.zero? && names.size == 1 && states.size == 1 &&
              names.first.match?(/\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+il\z/i) &&
              ['transfer locked', 'transfer allowed'].include?(states.first)
          :registered
        else
          :unknown
        end
      end

      property_supported :available? do
        status == :available
      end

      property_supported :registered? do
        status == :registered
      end


      # TODO: first changed record
      property_not_supported :created_on

      property_supported :updated_on do
        if content_for_scanner =~ /changed:\s+(.+)\n/
          t = content_for_scanner.scan(/changed:\s+(?:.+?) (\d+) \(.+\)\n/).flatten.last
          parse_time(t)
        end
      end

      property_not_supported :expires_on


      property_supported :nameservers do
        content_for_scanner.scan(/nserver:\s+(.+)\n/).flatten.map do |name|
          Parser::Nameserver.new(:name => name.strip)
        end
      end

    end

  end
end
