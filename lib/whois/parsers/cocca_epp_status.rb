require_relative 'registry_response_safety'

module Whois
  class Parsers
    # Current CoCCA responses annotate status values with exact EPP links and
    # can identify an absent query using a Domain Name echo plus one marker.
    module CoccaEppStatus
      include RegistryResponseSafety

      private

      def current_cocca_status
        text = content_for_scanner
        absent = text.scan(/^(?:The queried object does not exist:|Domain Status:)[ \t]*No Object Found[ \t]*$/i)
        return nil unless absent.any? || text.match?(/^Domain Status:.*https:\/\/icann\.org\/epp#/i)

        names = text.scan(/^Domain Name:[ \t]*([^\r\n]+)$/i).flatten.map(&:strip)
        return :unknown unless names.one? && names.first.match?(/\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+#{self.class::CURRENT_COCCA_SUFFIX}\z/i)

        statuses = text.scan(/^Domain Status:[ \t]*([^\r\n]+)$/i).flatten.map(&:strip)
        details = text.match?(/^(?:Creation Date|Updated Date|Registry Expiry Date|Name Server|Sponsoring Registrar):[ \t]*\S/i)
        return :available if absent.one? && statuses.all? { |value| value.casecmp('No Object Found').zero? } && !details
        return :unknown if absent.any?

        valid = statuses.all? do |status|
          status.match?(/\A(?<token>ok|active|(?:client|server)(?:Delete|Renew|Transfer|Update)Prohibited)(?:[ \t]+https:\/\/icann\.org\/epp#\k<token>)?\z/i)
        end
        present = statuses.any? { |status| status.match?(/\A(?:ok|active)(?:[ \t]|\z)/i) }
        valid && present ? :registered : :unknown
      end
    end
  end
end
