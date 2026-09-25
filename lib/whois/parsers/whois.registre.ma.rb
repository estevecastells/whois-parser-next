#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require_relative 'registry_response_safety'


module Whois
  class Parsers

    # Parser for the whois.registre.ma server.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisRegistreMa < Base
      include RegistryResponseSafety

      property_supported :status do
        classify_status
      end

      property_supported :available? do
        classify_status == :available
      end

      property_supported :registered? do
        classify_status == :registered
      end


      property_supported :created_on do
        if content_for_scanner =~ /domain:Created:(.+?)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :updated_on do
        if content_for_scanner =~ /domain:Updated:(.+?)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_not_supported :expires_on

      private

      def classify_status
        return :unknown if conflicting_evidence?

        return :registered if registered_evidence?
        return :available if available_evidence?

        :unknown
      end

      def conflicting_evidence?
        return false unless absence_markers.any?

        record_details_present? || legacy_record_evidence?
      end

      def registered_evidence?
        return false unless valid_domain_name_fields? && domain_names.one? && absence_markers.empty?

        current_record_evidence? || legacy_record_evidence?
      end

      def current_record_evidence?
        domain_status_values == ['clientTransferProhibited https://icann.org/epp#clientTransferProhibited']
      end

      def legacy_record_evidence?
        legacy_domain_names.one? &&
          content_for_scanner.match?(/^[ \t]*domain:Class-Name:domain[ \t]*$/i) &&
          content_for_scanner.match?(/^[ \t]*%ok[ \t]*$/i)
      end

      def available_evidence?
        absence_markers.one? && valid_domain_name_fields? && !record_details_present? &&
          !legacy_record_evidence?
      end

      def valid_domain_name_fields?
        fields = domain_name_field_values
        return false if domain_name_field? && fields.empty?

        fields.empty? || (fields.one? && domain_names.one?)
      end

      def domain_names
        (current_domain_names + legacy_domain_names).uniq
      end

      def domain_name_field_values
        content_for_scanner.scan(/^[ \t]*Domain Name:[ \t]*(\S+)[ \t]*$/i).flatten +
          content_for_scanner.scan(/^[ \t]*domain:Domain-Name:[ \t]*(\S+)[ \t]*$/i).flatten
      end

      def current_domain_names
        content_for_scanner.scan(
          /^[ \t]*Domain Name:[ \t]*((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+ma)[ \t]*$/i
        ).flatten.map(&:downcase)
      end

      def legacy_domain_names
        content_for_scanner.scan(
          /^[ \t]*domain:Domain-Name:[ \t]*((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+ma)[ \t]*$/i
        ).flatten.map(&:downcase)
      end

      def domain_status_values
        content_for_scanner.scan(/^[ \t]*Domain Status:[ \t]*(.+?)[ \t]*$/i).flatten
      end

      def absence_markers
        content_for_scanner.scan(
          /^[ \t]*(?:%error 230 No Objects Found|The queried object does not exist: No Object Found)[ \t]*$/i
        )
      end

      def domain_name_field?
        content_for_scanner.match?(/^[ \t]*(?:Domain Name:|domain:Domain-Name:)/i)
      end

      def record_details_present?
        content_for_scanner.match?(
          /^[ \t]*(?:Domain Status|Domain ID|Registrar|Creation Date|Updated Date|Registry Expiry Date|Name Server|domain:Class-Name|domain:ID|domain:Auth-Area):/i
        )
      end

    end

  end
end
