# frozen_string_literal: true

require_relative 'base'
require_relative 'registry_response_safety'

module Whois
  class Parsers
    # ANINF's current French-language registry response, observed 2026-10-19.
    class WhoisNicGa < Base
      include RegistryResponseSafety

      property_supported(:domain) { header_field('Nom de domaine')&.downcase }
      property_supported(:domain_id) { header_field('Domain ID') }
      property_supported(:status) do
        names = content_for_scanner.scan(/^Nom de domaine:[ \t]*(.+)$/).flatten
        missing = content_for_scanner.scan(/^%% NOT FOUND[ \t]*$/).size
        if missing == 1 && names.empty? && !header_field('Domain ID')
          :available
        elsif missing.zero? && names.size == 1 &&
              names.first.strip.match?(/\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.ga\z/i) &&
              header_field('Domain ID') && header_field('Statut') == 'actif' &&
              valid_creation_date?
          :registered
        else
          :unknown
        end
      end
      property_supported(:available?) { status == :available }
      property_supported(:registered?) { status == :registered }
      property_supported(:created_on) { header_date('Date de création') }
      property_supported(:updated_on) { header_date('Dernière modification') }
      property_supported(:expires_on) { header_date("Date d'expiration") }
      property_supported(:registrar) do
        name = header_field('Registrar')
        Parser::Registrar.new(name: name) if name
      end
      property_supported(:nameservers) do
        content_for_scanner.scan(/^Serveur de noms:[ \t]*(\S+)[ \t]*$/).flatten.map do |name|
          Parser::Nameserver.new(name: name.downcase)
        end
      end

      private

      def header_field(label)
        header = content_for_scanner.split(/^\[/, 2).first.to_s
        values = header.scan(/^#{Regexp.escape(label)}:[ \t]*(.+)$/).flatten.map(&:strip)
        values.first if values.size == 1 && !values.first.empty?
      end

      def header_date(label)
        value = header_field(label)
        parse_time(value) if value
      end

      def valid_creation_date?
        value = header_field('Date de création')
        value && value.match?(/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\z/) && Date.iso8601(value[0, 10]) && Time.iso8601(value)
      rescue ArgumentError
        false
      end
    end
  end
end
