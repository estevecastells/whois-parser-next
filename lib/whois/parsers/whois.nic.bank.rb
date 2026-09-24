require_relative 'base_icann_compliant'

module Whois
  class Parsers
    class WhoisNicBank < BaseIcannCompliant
      property_supported :status do
        if no_data_found?
          :available
        else
          super()
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
        content_for_scanner.lines.first.to_s.strip.casecmp?('No Data Found')
      end
    end
  end
end
