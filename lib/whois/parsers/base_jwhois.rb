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
        text = content_for_scanner
        domains = text.scan(/^domain:[ \t]*(\S+)[ \t]*\r?$/i).flatten
        missing = text.scan(/^NO OBJECT FOUND![ \t]*\r?\nobject:[ \t]*(\S+)[ \t]*\r?\ntype:[ \t]*([^\r\n]+)$/i)
        markers = text.scan(/^NO OBJECT FOUND![ \t]*\r?$/i).length
        return :unknown unless markers == missing.length

        if domains.empty?
          missing.one? && missing.first.last.strip.casecmp('domain').zero? &&
            missing.first.first.match?(/\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:gf|mq)\z/i) ? :available : :unknown
        elsif domains.one? && domains.first.match?(/\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:gf|mq)\z/i) && registered_evidence?
          # Referenced person objects may be absent while the domain exists.
          missing.all? { |name, type| type.strip.casecmp('person').zero? && !name.casecmp(domains.first).zero? } ? :registered : :unknown
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

      property_supported :nameservers do
        content_for_scanner.scan(/^nameserver:\s*(\S+)\s*$/i).flatten.map do |name|
          Parser::Nameserver.new(name: name.downcase)
        end
      end

      private

      def registered_evidence?
        content_for_scanner.match?(/^domain:\s*\S+/i) &&
          content_for_scanner.match?(/^(?:changed|nameserver):\s*\S+/i)
      end
    end
  end
end
