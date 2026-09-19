require_relative 'base_unsupported_registry'

module Whois
  class Parsers
    # Identity Digital does not expose .SOLUTIONS through this WHOIS endpoint.
    class WhoisNicSolutions < BaseUnsupportedRegistry
    end
  end
end
