require_relative 'whois.dk-hostmaster.dk'
require_relative 'registry_response_safety'

module Whois
  class Parsers
    # Direct parser for IANA's current .dk WHOIS host. The older
    # whois.dk-hostmaster.dk parser remains available for its legacy route.
    class WhoisPunktumDk < WhoisDkHostmasterDk
      include RegistryResponseSafety

      DOMAIN_LINE = /^Domain:[ \t]*(\S+)[ \t]*\r?$/i
      STATUS_LINE = /^Status:[ \t]*(\S+)[ \t]*\r?$/i
      ABSENCE_LINE = /\ANo entries found for the selected source\.[ \t]*\z/i
      REGISTERED_EVIDENCE = /^(Registered|Expires|Registrar|Hostname):[ \t]*\S/im
      RECORD_EVIDENCE = /^(?:Domain|DNS|Registered|Expires|Registrar|Registration period|VID|DNSSEC|Status|Hostname):[ \t]*\S/im

      property_supported :domain do
        content_for_scanner.scan(DOMAIN_LINE).flatten.first&.downcase
      end

      property_supported :status do
        body = content_for_scanner
        absence_count = body.lines.count { |line| line.chomp.match?(ABSENCE_LINE) }

        if absence_count.positive?
          absence_count == 1 && !body.match?(RECORD_EVIDENCE) ? :available : :unknown
        else
          domains = body.scan(DOMAIN_LINE).flatten
          statuses = body.scan(STATUS_LINE).flatten
          evidence_fields = body.scan(REGISTERED_EVIDENCE).flatten.map(&:downcase).uniq
          if domains.length == 1 && domains.first.downcase.end_with?('.dk') && statuses.length == 1 && evidence_fields.length >= 2
            case statuses.first.downcase
            when 'active' then :registered
            when 'deactivated' then :expired
            when 'reserved' then :reserved
            else :unknown
            end
          else
            :unknown
          end
        end
      end

      property_supported :available? do
        status == :available
      end

      property_supported :registered? do
        status == :registered
      end
    end
  end
end
