#--
# Ruby Whois
#++

require_relative 'base'
require_relative 'registry_response_safety'

module Whois
  class Parsers
    # Parser for the NIC Costa Rica WHOIS service.
    class WhoisNicCr < Base
      include RegistryResponseSafety

      property_supported :domain do
        content_for_scanner[/^domain:\s*(\S+)/i, 1]&.downcase
      end

      property_not_supported :domain_id

      property_supported :status do
        if available?
          :available
        elsif domain
          :registered
        else
          Whois::Parser.bug!(ParserError, "Unable to parse .cr response status.")
        end
      end

      property_supported :available? do
        content_for_scanner.match?(/^%ERROR:101:\s*no entries found\s*$/i) &&
          content_for_scanner.match?(/^%\s*No entries found\.?\s*$/i)
      end

      property_supported :registered? do
        status == :registered
      end

      property_supported :created_on do
        content_for_scanner[/^registered:\s*(\S+)/i, 1]&.then { |value| parse_time(value) }
      end

      property_supported :updated_on do
        content_for_scanner[/^changed:\s*(\S+)/i, 1]&.then { |value| parse_time(value) }
      end

      property_supported :expires_on do
        content_for_scanner[/^expire:\s*(\S+)/i, 1]&.then { |value| parse_time(value) }
      end

      property_supported :registrar do
        content_for_scanner[/^registrar:\s*(\S+)/i, 1]&.then do |name|
          Parser::Registrar.new(name: name)
        end
      end

      property_supported :nameservers do
        content_for_scanner.scan(/^nserver:\s*(\S+)/i).flatten.map do |name|
          Parser::Nameserver.new(name: name.downcase)
        end
      end
    end
  end
end
