require_relative 'whois.audns.net.au'
require_relative 'registry_response_safety'

module Whois
  class Parsers
    # Parser for the whois.auda.org.au server.
    class WhoisAudaOrgAu < WhoisAudnsNetAu
      include RegistryResponseSafety

      KNOWN_STATUSES = %w[
        clientDeleteProhibited clientHold clientRenewProhibited clientTransferProhibited
        clientUpdateProhibited inactive ok pendingCreate pendingDelete pendingRenew
        pendingRestore pendingTransfer pendingUpdate serverDeleteProhibited serverHold
        serverRenewProhibited serverTransferProhibited serverUpdateProhibited
      ].freeze

      property_supported :status do
        classify_status
      end

      property_supported :available? do
        classify_status == :available
      end

      property_supported :registered? do
        classify_status == :registered
      end

      private

      def classify_status
        cached_properties_fetch(:classified_status) do
          domain_values = content_for_scanner.scan(/^Domain Name:[ \t]*([^\r\n]+?)[ \t]*$/i).flatten
          domain = domain_values.length == 1 && domain_values.first.match?(/\A(?:[a-z0-9-]+\.)+au\z/i)
          statuses = content_for_scanner.scan(/^Status:[ \t]*([^\r\n]*)$/i).flatten.map(&:strip).reject(&:empty?)
          known_statuses = statuses.map { |value| value.split(/[ \t]/, 2).first }.all? do |value|
            KNOWN_STATUSES.include?(value)
          end
          record_fields = content_for_scanner.scan(/^(?:Registry Domain ID|Registrar Name|Name Server):[ \t]*\S[^\r\n]*$/i)
          has_record_fields = content_for_scanner.match?(/^(?:Domain Name|Registry Domain ID|Registrar Name|Status|Name Server):[ \t]*\S/i)
          available_marker = content_for_scanner.match?(/^Domain not found\.[ \t]*$/i)

          if available_marker && !has_record_fields
            :available
          elsif domain && !statuses.empty? && known_statuses && record_fields.length >= 2 && !available_marker
            :registered
          else
            :unknown
          end
        end
      end
    end
  end
end
