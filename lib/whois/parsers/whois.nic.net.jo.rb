# frozen_string_literal: true

require_relative 'base_cocca2'
require_relative 'registry_response_safety'
require 'whois/scanners/whois.nic.net.jo'

module Whois
  class Parsers
    # Jordan's official registry endpoint, observed 2026-10-19.
    class WhoisNicNetJo < BaseCocca2
      include RegistryResponseSafety
      self.scanner = Scanners::WhoisNicNetJo

      property_supported(:status) do
        names = content_for_scanner.scan(/^Domain Name:[ \t]*(.+)$/i).flatten.map(&:strip)
        absent = content_for_scanner.scan(/^No match for domain "([^"\n]+)"[ \t]*$/i).flatten
        statuses = content_for_scanner.scan(/^Domain Status:[ \t]*(.+)$/i).flatten.map(&:strip)
        valid_name = names.size == 1 && names.first.match?(/\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+jo\z/i)
        if valid_name && absent.size == 1 && absent.first.casecmp?(names.first) && statuses.empty? &&
            !content_for_scanner.match?(/^Creation Date:/i)
          :available
        elsif valid_name && absent.empty? && statuses == ['Active'] && valid_creation_date?
          :registered
        else
          :unknown
        end
      end
      property_supported(:available?) { status == :available }
      property_supported(:registered?) { status == :registered }

      private

      def valid_creation_date?
        values = content_for_scanner.scan(/^Creation Date:[ \t]*(.+)$/i).flatten.map(&:strip)
        values.size == 1 && values.first.match?(/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\z/) && Date.iso8601(values.first[0, 10]) && Time.iso8601(values.first)
      rescue ArgumentError
        false
      end
    end
  end
end
