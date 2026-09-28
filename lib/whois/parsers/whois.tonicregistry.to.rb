require_relative 'base_icann_compliant'

module Whois
  class Parsers
    # Parser for the whois.tonicregistry.to server.
    class WhoisTonicregistryTo < BaseIcannCompliant
      AVAILABLE_DOMAIN_LINE = /^>>> Domain (?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+to is available for registration$/i
      DOMAIN_PATTERN = /\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+to\z/i
      REGISTRATION_FIELD = /^[ \t]*(?:Domain Name|Registry Domain ID|Updated Date|Creation Date|Registry Expiry Date|Registrar(?: URL| IANA ID| Abuse Contact (?:Email|Phone))?|Domain Status|Name Server|DNSSEC):[ \t]*\S/i

      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: AVAILABLE_DOMAIN_LINE,
      }

      property_supported :status do
        if available_marker_count == 1
          :available
        elsif registered_record?
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

      def response_unavailable?
        super || ambiguous_availability_response?
      end

      private

      def available_marker_count
        content_for_scanner.lines.count { |line| line.match?(AVAILABLE_DOMAIN_LINE) }
      end

      def ambiguous_availability_response?
        marker_count = available_marker_count
        marker_count.positive? && (
          marker_count != 1 || content_for_scanner.match?(REGISTRATION_FIELD)
        )
      end

      def registered_record?
        response = content_for_scanner
        domains = response.scan(/^[ \t]*Domain Name:[ \t]*(.*?)[ \t]*$/i).flatten
        registry_ids = response.scan(/^[ \t]*Registry Domain ID:[ \t]*(.*?)[ \t]*$/i).flatten
        creation_dates = response.scan(/^[ \t]*Creation Date:[ \t]*(.*?)[ \t]*$/i).flatten
        registrars = response.scan(/^[ \t]*Registrar:[ \t]*(.*?)[ \t]*$/i).flatten
        nameservers = response.scan(/^[ \t]*Name Server:[ \t]*(.*?)[ \t]*$/i).flatten

        domains.one? && domains.first.match?(DOMAIN_PATTERN) &&
          registry_ids.one? && !registry_ids.first.empty? &&
          creation_dates.one? && parse_time(creation_dates.first) &&
          registrars.one? && !registrars.first.empty? &&
          nameservers.any? { |nameserver| !nameserver.empty? }
      end
    end
  end
end
