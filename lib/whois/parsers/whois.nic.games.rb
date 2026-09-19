require_relative 'base_unsupported_registry'

module Whois
  class Parsers
    # Identity Digital does not expose .GAMES through this WHOIS endpoint.
    class WhoisNicGames < BaseUnsupportedRegistry
    end
  end
end
