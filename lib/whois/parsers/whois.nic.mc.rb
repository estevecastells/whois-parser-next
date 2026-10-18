require_relative 'base'
require_relative 'registry_response_safety'

module Whois
  class Parsers
    class WhoisNicMc < Base
      include RegistryResponseSafety

      property_supported(:domain) { content_for_scanner[/^Domain[ \t]*:[ \t]*(\S+)[ \t]*\r?$/i, 1]&.downcase }

      property_supported :status do
        text = content_for_scanner
        names = text.scan(/^Domain[ \t]*:[ \t]*(\S+)[ \t]*\r?$/i).flatten
        absent = text.scan(/^>> No data found for domain : (\S+)[ \t]*\r?$/i).flatten
        dates = text.scan(/^Created[ \t]*:[ \t]*([^\r\n]+)$/i).flatten
        statuses = text.scan(/^Status[ \t]*:[ \t]*([^\r\n]+)$/i).flatten.map(&:strip)
        if absent.any?
          absent.one? && valid_mc_domain?(absent.first) && names.empty? && dates.empty? && statuses.empty? ? :available : :unknown
        else
          valid_date = dates.one? && begin
            !!parse_time(dates.first.strip)
          rescue ArgumentError
            false
          end
          names.one? && valid_mc_domain?(names.first) && statuses == ['ACTIVE'] && valid_date ? :registered : :unknown
        end
      end
      property_supported(:registered?) { status == :registered }
      property_supported(:available?) { status == :available }
      property_supported :created_on do
        value = content_for_scanner[/^Created[ \t]*:[ \t]*([^\r\n]+)$/i, 1]
        parse_time(value.strip) if value
      end
      property_supported :expires_on do
        value = content_for_scanner[/^Expires on[ \t]*:[ \t]*([^\r\n]+)$/i, 1]
        parse_time(value.strip) if value
      end

      private

      def valid_mc_domain?(name)
        name.match?(/\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+mc\z/i)
      end
    end
  end
end
