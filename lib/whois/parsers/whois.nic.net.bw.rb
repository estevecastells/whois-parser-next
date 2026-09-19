require_relative 'base_cocca2'

module Whois
  class Parsers
    # Parser for the Botswana WHOIS service. Policy responses are intentionally
    # left as unknown by BaseCocca2 instead of being inferred as registration
    # or availability.
    class WhoisNicNetBw < BaseCocca2
    end
  end
end
