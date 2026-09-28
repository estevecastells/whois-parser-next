#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'


module Whois
  class Parsers

    # Parser for the whois.eu server.
    #
    class WhoisEu < Base

      property_supported :domain do
        if content_for_scanner =~ /Domain:\s+(.+)\n/
          "#{::Regexp.last_match(1).downcase}"
        end
      end

      property_not_supported :domain_id


      property_supported :status do
        classify_status
      end

      property_supported :available? do
        classify_status == :available
      end

      property_supported :registered? do
        classify_status == :registered
      end


      property_not_supported :created_on

      property_not_supported :updated_on

      property_not_supported :expires_on


      property_supported :registrar do
        if content_for_scanner =~ /Registrar:\s((.+\n)+)\n/
          lines = ::Regexp.last_match(1)
          Parser::Registrar.new(
              name:         lines.slice(/Name:\s+(.+)/, 1),
              url:          lines.slice(/Website:\s+(.+)/, 1)
          )
        end
      end

      property_not_supported :registrant_contacts

      property_not_supported :admin_contacts

      # Technical Contact
      #
      # Technical:
      # Name: DNS Admin
      # Organisation: Google Inc.
      # Language: en
      # Phone: +1.6506234000
      # Fax: +1.6506188571
      # Email: dns-admin@google.com
      #
      property_supported :technical_contacts do
        if content_for_scanner =~ /Technical:\s((.+\n)+)\n/
          lines = ::Regexp.last_match(1)
          Parser::Contact.new(
            :type         => Parser::Contact::TYPE_TECHNICAL,
            :id           => nil,
            :name         => lines.slice(/Name:\s*(.*)/, 1),
            :organization => lines.slice(/Organisation:\s*(.*)/, 1),
            :phone        => lines.slice(/Phone:\s*(.*)/, 1),
            :fax          => lines.slice(/Fax:\s*(.*)/, 1),
            :email        => lines.slice(/Email:\s*(.*)/, 1)
          )
        end
      end


      # Nameservers are listed in the following formats:
      #
      #   Name servers:
      #   dns1.servicemagic.eu
      #   dns2.servicemagic.eu
      #
      #   Name servers:
      #   dns1.servicemagic.eu (91.121.133.61)
      #   dns2.servicemagic.eu (91.121.103.77)
      #
      property_supported :nameservers do
        if content_for_scanner =~ /Name\sservers:\s((.+\n)+)\n/
          ::Regexp.last_match(1).split("\n").map do |line|
            if line.strip =~ /(.+) \((.+)\)/
              Parser::Nameserver.new(:name => ::Regexp.last_match(1), :ipv4 => ::Regexp.last_match(2))
            else
              Parser::Nameserver.new(:name => line.strip)
            end
          end
        end
      end


      # Checks whether the response has been throttled.
      #
      # @return [Boolean]
      #
      # @example
      #   -1: Still in grace period, wait 7777777 seconds
      #
      def response_throttled?
        !!(content_for_scanner =~ /Still in grace period/)
      end

      private

      def classify_status
        cached_properties_fetch(:classified_status) do
          status_values = content_for_scanner.scan(/^Status:[ \t]*([^\r\n]*)$/i).flatten.map(&:strip)
          available = status_values == ['AVAILABLE']
          domain_values = content_for_scanner.scan(/^Domain:[ \t]*([^\r\n]+?)[ \t]*$/i).flatten.map(&:downcase)
          domain = domain_values.length == 1 && domain_values.first.match?(/\A(?:[a-z0-9-]+\.)+eu\z/i)
          echoed_queries = content_for_scanner.scan(/^%?[ \t]*WHOIS[ \t]+((?:[a-z0-9-]+\.)+eu)[ \t]*$/i).flatten.map(&:downcase)
          identity_matches = echoed_queries.empty? || (echoed_queries.length == 1 && echoed_queries.first == domain_values.first)
          registrar = content_for_scanner.match?(/^Registrar:[ \t]*\r?\n[ \t]+Name:[ \t]*\S[^\r\n]*$/i)
          nameservers = content_for_scanner.match?(
            /^Name servers:[ \t]*\r?\n(?:[ \t]+(?:[a-z0-9-]+\.)+[a-z0-9-]+(?:[ \t]+\([^\r\n()]+\))?[ \t]*\r?\n?)+/i
          )
          record = registrar || nameservers
          record_fields = content_for_scanner.match?(/^(?:Registrar|Name servers|Registrant|Onsite(?:\(s\))?|Technical|Created|Creation date|Updated|Last updated|Expires|Expiration date):/i)
          denied_or_throttled = content_for_scanner.match?(
            /\b(?:access\s+denied|permission\s+denied|not\s+authori[sz]ed|unauthori[sz]ed|not\s+allowed|too\s+many\s+requests|rate[- ]?limit(?:ed)?|temporarily\s+unavailable|service\s+unavailable|try\s+again\s+later|still\s+in\s+grace\s+period)\b/i
          )

          if !denied_or_throttled && available && domain && identity_matches && !record_fields
            :available
          elsif !denied_or_throttled && domain && identity_matches && record && (status_values.empty? || status_values == ['REGISTERED'])
            :registered
          else
            :unknown
          end
        end
      end

    end

  end
end
