#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_cocca'


module Whois
  class Parsers

    # Parser for the whois.netcom.cm server.
    class WhoisNetcomCm < BaseCocca

      status_mapping.merge!({
          "suspended" => :registered,
          "active https://icann.org/epp#active" => :registered,
      })

      property_supported :domain do
        content_for_scanner[/^Domain Name:\s*(\S+)/i, 1]&.downcase || super()
      end

      property_supported :status do
        return :available if available?

        value = content_for_scanner[/^Domain Status:\s*(.+)$/i, 1]
        if value
          normalized = value.downcase.sub(%r{\s+https?://.*\z}, '')
          return self.class.status_mapping[normalized] if self.class.status_mapping.key?(normalized)
        end

        super()
      end

      property_supported :available? do
        !!(content_for_scanner =~ /^(?:The queried object does not exist:\s*No Object Found|Status:\s*Not Registered)$/i)
      end

      property_supported :nameservers do
        current = content_for_scanner.scan(/^Name Server:\s*(\S+)/i).flatten.map do |name|
          Parser::Nameserver.new(name: name.downcase)
        end
        current.empty? ? super() : current
      end

    end

  end
end
