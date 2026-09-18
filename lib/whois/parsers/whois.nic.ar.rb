#--
# Ruby Whois
#++

require_relative 'base'

module Whois
  class Parsers

    # Parser for the compact port-43 response from NIC Argentina.
    class WhoisNicAr < Base

      property_supported :domain do
        content_for_scanner[/^domain:\s+(.+)$/i, 1]&.strip
      end

      property_supported :status do
        if available?
          :available
        elsif domain
          :registered
        else
          :unknown
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /El dominio no se encuentra registrado/i)
      end

      property_supported :registered? do
        !available? && !domain.nil?
      end

      property_supported :created_on do
        parse_time(content_for_scanner[/^registered:\s+(.+)$/i, 1])
      end

      property_supported :updated_on do
        parse_time(content_for_scanner[/^changed:\s+(.+)$/i, 1])
      end

      property_supported :expires_on do
        parse_time(content_for_scanner[/^expire:\s+(.+)$/i, 1])
      end

      property_supported :nameservers do
        []
      end

    end

  end
end
