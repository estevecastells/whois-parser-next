#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_icb'


module Whois
  class Parsers

    # Parser for the whois.nic.sh server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicSh < BaseIcb
      self.scanner = Scanners::BaseIcannCompliant, {
          pattern_available: /^(?:NOT FOUND|Domain not found\.)[ \t]*\r?$/i,
      }

      property_supported :status do
        if absence_marker_count.positive?
          available? ? :available : :unknown
        else
          super()
        end
      end

      property_supported :available? do
        absence_marker_count == 1 && !record_details_present?
      end

      private

      def absence_marker_count
        content_for_scanner.scan(/^(?:NOT FOUND|Domain not found\.)[ \t]*\r?$/i).length
      end

      def record_details_present?
        content_for_scanner.match?(
          /^[ \t]*(?:Domain Name|Registry Domain ID|Domain Status|Creation Date|Updated Date|Registry Expiry Date|Registrar|Name Server):/i
        )
      end
    end

  end
end
