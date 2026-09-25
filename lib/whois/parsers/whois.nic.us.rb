#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_shared2'


module Whois
  class Parsers

    # Parser for the whois.nic.us server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicUs < BaseShared2
      # The .us registry says a missing record does not establish availability.
      # Keep its no-record responses unknown and require record status evidence
      # before reporting a domain as registered.
      property_supported :status do
        statuses = Array.wrap(node("Domain Status"))
        registered_evidence? ? statuses : :unknown
      end

      property_supported :available? do
        false
      end

      property_supported :registered? do
        registered_evidence?
      end

      private

      def registered_evidence?
        domain_name = node("Domain Name").to_s.strip
        statuses = Array.wrap(node("Domain Status")).reject { |value| value.to_s.strip.empty? }

        domain_name.match?(/\A\S+\.us\z/i) && statuses.any? { |status| epp_status?(status) }
      end

      def epp_status?(status)
        status.to_s.strip.match?(
          %r{\A(?<status>(?:client|server|pending)[A-Z][A-Za-z]*)(?:\s+https?://icann\.org/epp#\k<status>)?\z}
        )
      end
    end

  end
end
