require_relative 'base_icann_compliant'

module Whois
  class Parsers
    # Conservative parser for American Express's restricted .OPEN registry.
    # The registry's exact "No Data Found" response is not public availability:
    # the published policy restricts registrations to the operator, qualified
    # affiliates, and trademark licensees.
    class WhoisNicOpen < BaseIcannCompliant
      DOMAIN_PATTERN = /\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+open\z/i
      DOMAIN_ID_PATTERN = /\AD\d+-OPEN\z/i
      NO_DATA_MARKER = /^[ \t]*No Data Found[ \t]*$/i
      RECORD_FIELD = /^[ \t]*(?:Domain Name|Registry Domain ID|Updated Date|Creation Date|Registry Expiry Date|Registrar|Registrar IANA ID|Domain Status|Name Server|DNSSEC):[ \t]*\S/i
      REGISTRAR_NAME = /\AAmerican Express Travel Related Services, Inc\.\z/i
      NAMESERVER_PATTERN = /\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?\z/i

      property_supported :domain do
        values = field_values('Domain Name')
        values.one? && values.first.match?(DOMAIN_PATTERN) ? values.first.downcase : nil
      end

      property_supported :domain_id do
        values = field_values('Registry Domain ID')
        values.one? && values.first.match?(DOMAIN_ID_PATTERN) ? values.first : nil
      end

      property_supported :status do
        classify_status
      end

      property_supported :available? do
        classify_status == :available
      end

      property_supported :registered? do
        classify_status == :registered
      end

      property_supported :expires_on do
        values = field_values('Registry Expiry Date')
        parse_time(values.first) if values.one?
      end

      def response_unavailable?
        body = content_for_scanner
        marker_count = body.lines.count { |line| line.match?(NO_DATA_MARKER) }

        super || (marker_count.positive? && (marker_count != 1 || body.match?(RECORD_FIELD)))
      end

      private

      def classify_status
        cached_properties_fetch(:classified_status) do
          complete_registered_record? ? :registered : :unknown
        end
      end

      def complete_registered_record?
        domains = field_values('Domain Name')
        ids = field_values('Registry Domain ID')
        registrars = field_values('Registrar')
        registrar_ids = field_values('Registrar IANA ID')

        domains.one? && domains.first.match?(DOMAIN_PATTERN) &&
          ids.one? && ids.first.match?(DOMAIN_ID_PATTERN) &&
          registrars.one? && registrars.first.match?(REGISTRAR_NAME) &&
          registrar_ids == ['9999'] &&
          valid_date_field?('Creation Date') &&
          valid_date_field?('Updated Date') &&
          valid_date_field?('Registry Expiry Date') &&
          valid_nameservers? && field_values('Domain Status').any?
      end

      def valid_date_field?(name)
        values = field_values(name)
        return false unless values.one?

        Time.iso8601(values.first)
        true
      rescue ArgumentError
        false
      end

      def valid_nameservers?
        values = field_values('Name Server')
        values.any? && values.all? { |value| value.match?(NAMESERVER_PATTERN) }
      end

      def field_values(name)
        content_for_scanner.scan(/^[ \t]*#{Regexp.escape(name)}:[ \t]*(.*?)[ \t\r]*$/i).flatten
      end
    end
  end
end
