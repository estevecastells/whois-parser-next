#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_cocca2'


module Whois
  class Parsers

    # Parser for the whois.nic.ms server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicMs < BaseCocca2
      property_supported :status do
        statuses = Array.wrap(node("Domain Status")).map do |value|
          value.to_s.split.first.to_s.downcase
        end

        return :available if content_for_scanner =~ /^The queried object does not exist: No Object Found/i
        return :available if content_for_scanner =~ /^Domain Status:\s+No Object Found/i
        return :registered if statuses.include?("ok") || statuses.include?("active")
        return :registered if statuses.any? && statuses.all? { |status| status.match?(/\A(?:client|server)(?:delete|transfer|update|renew)prohibited\z/) }

        Whois::Parser.bug!(ParserError, "Unknown status `#{statuses.join(', ')}'.")
      end
    end

  end
end
