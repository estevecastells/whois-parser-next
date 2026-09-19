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

    # Parser for the whois.nic.nf server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicNf < BaseCocca2
      # The current CoCCA endpoint omits `Domain Status` for an authoritative
      # no-object response. Keep that response available instead of allowing
      # the base parser to return an unknown status.
      property_supported :status do
        if content_for_scanner.match?(/^The queried object does not exist: No Object Found\b/i)
          :available
        else
          list = Array.wrap(node("Domain Status")).map(&:downcase)
          if list.include?("no object found")
            :available
          elsif list.include?("ok") || list.any? { |value| value.match?(/\Aactive(?:\s|\z)/) }
            :registered
          else
            :unknown
          end
        end
      end

      property_supported :available? do
        status == :available
      end

      property_supported :registered? do
        status == :registered
      end
    end

  end
end
