#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_icann_compliant'


module Whois
  class Parsers

    # Parser for the whois.donuts.com server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisUniregistryNet < BaseIcannCompliant
      AVAILABLE_DOMAIN_LINE = /^>>> Domain (?:"[^"\r\n]+"|[^\s\r\n]+) is available for registration[ \t]*$/
      RECORD_EVIDENCE = /^[ \t]*(?:Domain Name|Domain ID|Registry Domain ID|Creation Date|Registrar|Sponsoring Registrar|Name Server):[ \t]*\S/i

      self.scanner = Scanners::BaseIcannCompliant, {
          pattern_available: AVAILABLE_DOMAIN_LINE,
      }


      property_supported :domain_id do
        node('Domain ID')
      end


      property_supported :expires_on do
        node('Registry Expiry Date') do |value|
          parse_time(value)
        end
      end


      property_supported :registrar do
        return unless node('Sponsoring Registrar')

        Parser::Registrar.new(
            id:           node('Sponsoring Registrar IANA ID'),
            name:         node('Sponsoring Registrar'),
            organization: node('Sponsoring Registrar')
        )
      end

      # Tucows returns this notice when the selected registry interface does
      # not support the queried TLD. It is not evidence that the domain is
      # registered or available.
      def response_unavailable?
        super || content_for_scanner.match?(
          /^(?:>>> Tld not supported by this registry interface|TLD is not supported\.)$/i
        ) || ambiguous_availability_response?
      end


      private

      def ambiguous_availability_response?
        marker_count = content_for_scanner.lines.count do |line|
          line.match?(AVAILABLE_DOMAIN_LINE)
        end

        marker_count.positive? && (
          marker_count != 1 || content_for_scanner.match?(RECORD_EVIDENCE)
        )
      end

      def build_contact(element, type)
        if (contact = super)
          contact.id = node("#{element} ID")
        end
        contact
      end

    end

  end
end
