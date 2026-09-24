require_relative 'base_icann_compliant'

module Whois
  class Parsers
    # Conservative ICANN-style parser shared by the package-3 registries.
    # The absence markers are complete lines observed in current port-43
    # responses. Empty, denied, and throttled responses remain unavailable via
    # RegistryResponseSafety inherited from BaseIcannCompliant.
    class BaseTop1000Icann < BaseIcannCompliant
      AVAILABLE_MARKERS = [
        /^No Data Found\s*$/i,
        /^The queried object does not exist:\s*(?:DOMAIN NOT FOUND|no matching objects found)\s*$/i,
        /^>>> Domain \S+ is available for registration\s*$/i,
        /^Domain not found\s*$/i,
        /^%% NOT FOUND\s*$/i,
      ].freeze

      RESERVED_MARKERS = [
        /^Reserved Domain Name\s*$/i,
        /^This name is reserved by the Registry\.\s*$/i,
      ].freeze

      property_supported :available? do
        AVAILABLE_MARKERS.any? { |marker| content_for_scanner.match?(marker) }
      end

      property_supported :reserved? do
        RESERVED_MARKERS.any? { |marker| content_for_scanner.match?(marker) }
      end

      # `reserved?` is intentionally a parser predicate rather than a public
      # record property. BaseIcannCompliant consults it while determining the
      # status of a reserved registry response.
      def reserved?
        RESERVED_MARKERS.any? { |marker| content_for_scanner.match?(marker) }
      end
    end
  end
end
