require_relative 'base'
require_relative 'registry_response_safety'

module Whois
  class Parsers
    # Minimal parser contract for JWhoisServer responses used by the French
    # overseas registries.  Registration is reported only from a domain line;
    # the registry's explicit NO OBJECT FOUND marker is the sole absence proof.
    class BaseJwhois < Base
      include RegistryResponseSafety

      property_supported :domain do
        content_for_scanner[/^domain:\s*(\S+)\s*$/i, 1]&.downcase
      end

      property_supported :status do
        if available?
          :available
        elsif content_for_scanner.match?(/^domain:\s*\S+/i)
          :registered
        else
          :unknown
        end
      end

      property_supported :available? do
        content_for_scanner.match?(/^NO OBJECT FOUND!\s*$/i)
      end

      property_supported :registered? do
        status == :registered
      end

      property_supported :nameservers do
        content_for_scanner.scan(/^nameserver:\s*(\S+)\s*$/i).flatten.map do |name|
          Parser::Nameserver.new(name: name.downcase)
        end
      end
    end
  end
end
