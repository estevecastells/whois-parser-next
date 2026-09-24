require_relative 'whois.cira.ca'
require_relative 'registry_response_safety'

module Whois
  class Parsers
    # CIRA-shaped registries use the same record scanner, but an unexpected
    # non-record response must remain unknown rather than becoming a parser
    # error that callers might accidentally treat as registration.
    class BaseCiraRegistry < WhoisCiraCa
      include RegistryResponseSafety

      property_supported :status do
        super()
      rescue ParserError
        :unknown
      end
    end
  end
end
