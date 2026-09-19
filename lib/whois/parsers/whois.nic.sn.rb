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
    # = whois.nic.sn parser
    #
    # Parser for the whois.nic.sn server.
    #
    class WhoisNicSn < Base
      include RegistryResponseSafety

      property_not_supported :disclaimer

      property_supported :domain do
        if registered? && content_for_scanner =~ /(?:Domain|Nom de domaine):\s+(.+)\n/i
          ::Regexp.last_match(1).strip
        elsif available? and content_for_scanner =~ /Domain (.+?) not found/
          ::Regexp.last_match(1)
        end
      end

      property_not_supported :domain_id


      property_supported :status do
        if available?
          :available
        elsif content_for_scanner.match?(/^(?:Domain|Nom de domaine):\s+\S+/i) &&
              content_for_scanner.match?(/^(?:Created|Statut|Status):\s+\S+/i)
          :registered
        else
          :unknown
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /^Domain \S+ not found\s*$/i ||
          content_for_scanner =~ /^%% NOT FOUND\s*$/i)
      end

      property_supported :registered? do
        status == :registered
      end


      property_supported :created_on do
        if content_for_scanner =~ /Created:\s+(.+)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_not_supported :updated_on

      property_not_supported :expires_on


      property_supported :registrar do
        if content_for_scanner =~ /Registrar:\s+(.+)\n/
          Parser::Registrar.new(
              :id           => ::Regexp.last_match(1),
              :name         => ::Regexp.last_match(1)
          )
        end
      end


      property_supported :registrant_contacts do
        if content_for_scanner =~ /Owner's handle:\s+(.+)\n/
          build_contact(::Regexp.last_match(1), Parser::Contact::TYPE_REGISTRANT)
        end
      end

      property_supported :admin_contacts do
        if content_for_scanner =~ /Administrative Contact's handle:\s+(.+)\n/
          build_contact(::Regexp.last_match(1), Parser::Contact::TYPE_ADMINISTRATIVE)
        end
      end

      property_supported :technical_contacts do
        if content_for_scanner =~ /Technical Contact's handle:\s+(.+)\n/
          build_contact(::Regexp.last_match(1), Parser::Contact::TYPE_TECHNICAL)
        end
      end


      property_supported :nameservers do
        content_for_scanner.scan(/Nameserver:\s+(.+)\n/).flatten.map do |name|
          Parser::Nameserver.new(:name => name)
        end
      end


      private

      def build_contact(string, type)
        Parser::Contact.new(
            :type => type,
            :id => string,
            :name => string
        )
      end

    end

  end
end
