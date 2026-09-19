#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_whoisd'


module Whois
  class Parsers

    # Parser for the whois.nic.fo server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicFo < BaseWhoisd

      property_not_supported :registrar

      # whois.nic.fo is using an old whoisd version.
      property_supported :technical_contacts do
        node('tech-c') do |value|
          build_contact(value, Parser::Contact::TYPE_TECHNICAL)
        end
      end


      # whois.nic.fo is using an old whoisd version.
      property_supported :nameservers do
        Array.wrap(node('nserver')).map do |line|
          Parser::Nameserver.new(:name => line.strip)
        end
      end

      # The endpoint now serves an ICANN-style record while retaining the
      # historical whoisd endpoint and parser contract. Normalize only the
      # current key/value subset into the format understood by BaseWhoisd.
      def content
        raw = super
        return "%ERROR:101: no entries found\n" if raw.match?(/\AThe queried object does not exist: DOMAIN NOT FOUND\b/i)
        return raw unless raw.match?(/\ADomain Name:/i)

        fields = raw.lines.filter_map do |line|
          key, value = line.split(':', 2)
          next unless value

          value = value.strip
          case key.downcase
          when 'domain name' then "domain: #{value.downcase}\n"
          when 'creation date' then "registered: #{value}\n"
          when 'updated date' then "changed: #{value}\n"
          when 'registry expiry date' then "expire: #{value}\n"
          when 'name server' then "nserver: #{value.downcase}\n"
          when 'domain status' then "status: paid and in zone\n"
          end
        end

        fields.join
      end

    end

  end
end
