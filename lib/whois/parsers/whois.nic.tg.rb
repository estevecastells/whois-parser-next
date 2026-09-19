require_relative 'base'
require_relative 'registry_response_safety'

module Whois
  class Parsers
    # Togo's JWhoisServer emits a repeated, label-aligned record rather than
    # the key/value layout used by most modern gTLDs.
    class WhoisNicTg < Base
      include RegistryResponseSafety

      property_supported :domain do
        content_for_scanner[/^Domain:\.*\s*(\S+)\s*$/i, 1]
      end

      property_supported :status do
        if content_for_scanner.match?(/^NO OBJECT FOUND!\s*$/i)
          :available
        elsif content_for_scanner.match?(/^Domain:\.*\s*\S+/i) &&
              content_for_scanner.match?(/^Status:\.*\s*Activ(?:&eacute;|é)/i)
          :registered
        else
          :unknown
        end
      end

      property_supported :available? do
        status == :available
      end

      property_supported :registered? do
        status == :registered
      end

      property_supported :created_on do
        parse_time(content_for_scanner[/^Activation:\.*\s*(\S+)\s*$/i, 1])
      end

      property_supported :expires_on do
        parse_time(content_for_scanner[/^Expiration:\.*\s*(\S+)\s*$/i, 1])
      end

      property_supported :nameservers do
        content_for_scanner.scan(/^Name Server \(DB\):\.*\s*(\S+)\s*$/i).flatten.map do |name|
          Parser::Nameserver.new(name: name.downcase)
        end
      end
    end
  end
end
