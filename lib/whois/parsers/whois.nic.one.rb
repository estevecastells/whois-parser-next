require_relative 'base_icann_compliant'

module Whois
  class Parsers

    # The .one registry uses the ICANN WHOIS shape for records, but its
    # no-record response is a short "No Data Found" line before the standard
    # footer. Keep that exact evidence separate from an unparseable response.
    class WhoisNicOne < BaseIcannCompliant
      property_supported :status do
        if no_data_found?
          :available
        elsif registered_response?
          :registered
        else
          :unknown
        end
      end

      property_supported :available? do
        status == :available
      end

      property_supported :registered? do
        status == :registered
      end

      private

      def no_data_found?
        content_for_scanner.lines.first.to_s.strip.casecmp?("No Data Found")
      end

      def registered_response?
        content_for_scanner.match?(/^Domain Name:\s+\S+/) &&
          content_for_scanner.match?(/^Domain Status:\s+\S+/)
      end
    end

  end
end
