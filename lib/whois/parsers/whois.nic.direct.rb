require_relative 'base_unsupported_registry'

module Whois
  class Parsers
    # Identity Digital does not expose .DIRECT through this WHOIS endpoint.
    class WhoisNicDirect < BaseUnsupportedRegistry
    end
  end
end
