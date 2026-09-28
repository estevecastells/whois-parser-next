require_relative 'whois.pir.org'
require_relative 'registry_response_safety'

module Whois
  class Parsers
    # IANA currently delegates .org WHOIS to whois.publicinterestregistry.org.
    # Its field format matches the legacy whois.pir.org parser.
    class WhoisPublicinterestregistryOrg < WhoisPirOrg
      include RegistryResponseSafety

      DOMAIN_LINE = /^Domain Name:[ \t]*(\S+)[ \t]*\r?$/i
      ABSENCE_LINE = /\ADomain not found\.[ \t]*\z/i
      REGISTERED_EVIDENCE = /^(Registry Domain ID|Creation Date|Updated Date|Registry Expiry Date|Registrar(?: IANA ID)?|Domain Status):[ \t]*\S/im
      RECORD_EVIDENCE = /^(?:Domain Name|Registry Domain ID|Creation Date|Updated Date|Registry Expiry Date|Registrar(?: IANA ID)?|Domain Status|Name Server):[ \t]*\S/im
      LEGACY_THROTTLE_LINE = /^[ \t]*WHOIS LIMIT EXCEEDED\b/i

      # WhoisPirOrg has its own scanner-backed throttle check. Call the shared
      # line guard directly as that inherited override parses the whole body.
      # Preserve its established PIR marker without parsing unrelated lines.
      def response_throttled?
        body = content_for_scanner
        body.match?(LEGACY_THROTTLE_LINE) ||
          RegistryResponseSafety.instance_method(:response_throttled?).bind_call(self)
      end

      property_supported :status do
        body = content_for_scanner
        absence_count = body.lines.count { |line| line.chomp.match?(ABSENCE_LINE) }

        if absence_count.positive?
          absence_count == 1 && !body.match?(RECORD_EVIDENCE) ? :available : :unknown
        else
          domains = body.scan(DOMAIN_LINE).flatten
          evidence_fields = body.scan(REGISTERED_EVIDENCE).flatten.map(&:downcase).uniq
          if domains.length == 1 && domains.first.downcase.end_with?('.org') && evidence_fields.length >= 2
            :registered
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
