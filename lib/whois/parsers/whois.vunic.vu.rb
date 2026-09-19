require_relative 'base_unsupported_registry'

module Whois
  class Parsers
    # The configured .vu endpoint rejects valid-looking queries as invalid.
    # Until a real registry record is observed, expose this as unavailable,
    # never as either availability or registration.
    class WhoisVunicVu < BaseUnsupportedRegistry
      def response_unavailable?
        content_for_scanner.match?(/The domain \S+\s*\n\s*is not valid!/i)
      end
    end
  end
end
