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

    # Parser for the whois.aeda.net.ae server.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisAedaNetAe < Base
      include RegistryResponseSafety

      # The registry answers rate-limited clients with a single "BLACKLISTED:"
      # line. That reply carries no domain data, so it must not be read as
      # either registered or available.
      def response_throttled?
        super || content_for_scanner.match?(/^BLACKLISTED:/i)
      end

      property_supported :status do
        if content_for_scanner =~ /Status:\s+(.+?)\n/
          case ::Regexp.last_match(1).strip.downcase
          when "ok", "clientdeleteprohibited", "clientupdateprohibited" then :registered
          else
            Whois::Parser.bug!(ParserError, "Unknown status `#{::Regexp.last_match(1)}'.")
          end
        else
          :available
        end
      end

      property_supported :available? do
        content_for_scanner.strip == "No Data Found" ||
          content_for_scanner.strip.casecmp("Domain not found.").zero?
      end

      property_supported :registered? do
        !available?
      end


      property_not_supported :created_on

      property_not_supported :updated_on

      property_not_supported :expires_on


      property_supported :registrar do
        id   = field("Registrar ID")
        name = field("Registrar Name")
        Parser::Registrar.new(id: id, name: name) if id || name
      end


      property_supported :registrant_contacts do
        build_contact("Registrant", Parser::Contact::TYPE_REGISTRANT)
      end

      property_not_supported :admin_contacts

      property_supported :technical_contacts do
        build_contact("Tech", Parser::Contact::TYPE_TECHNICAL)
      end


      property_supported :nameservers do
        content_for_scanner.scan(/Name Server:\s+(.+)\n/).flatten.map do |name|
          Parser::Nameserver.new(:name => name)
        end
      end


      private

      def field(label)
        content_for_scanner[/^#{label}:[ \t]+(.+)$/, 1]&.strip.presence
      end

      # A contact is the "<Role> Contact ID/Name/Organisation" lines. The
      # registry publishes no contact email over port 43: the "Contact Email"
      # line of the legacy layout only pointed to the web WHOIS, so it is not
      # read.
      def build_contact(role, type)
        id           = field("#{role} Contact ID")
        name         = field("#{role} Contact Name")
        organization = field("#{role} Contact Organisation")
        return [] unless id || name || organization

        [Parser::Contact.new(type: type, id: id, name: name, organization: organization)]
      end

    end

  end
end
