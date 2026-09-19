require_relative 'base_unsupported_registry'

module Whois
  class Parsers
    # Identity Digital does not expose .TOOLS through this WHOIS endpoint.
    class WhoisNicTools < BaseUnsupportedRegistry
    end
  end
end
