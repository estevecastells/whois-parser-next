require_relative 'base'

module Whois
  class Parsers
    # SSNIC returns an explicit no-object marker for an absent name. A
    # prohibited string is kept unknown, not registered.
    class WhoisNicSs < Base
      property_supported :status do
        if available?
          :available
        elsif content_for_scanner.match?(/^Domain Status:\s+Prohibited String\b/i)
          :unknown
        elsif registered_evidence?
          :registered
        else
          :unknown
        end
      end

      property_supported :available? do
        !!content_for_scanner.match?(/^The queried object does not exist:\s*No Object Found\s*$/i)
      end

      property_supported :registered? do
        status == :registered
      end

      private

      def registered_evidence?
        content_for_scanner.match?(/^Domain Name:\s+\S+/i) &&
          !content_for_scanner.match?(/^Domain Status:\s+Prohibited String\b/i)
      end
    end
  end
end
