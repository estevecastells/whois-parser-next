require_relative 'base_unsupported_registry'

module Whois
  class Parsers
    # Identity Digital does not expose .SOFTWARE through this WHOIS endpoint.
    class WhoisNicSoftware < BaseUnsupportedRegistry
    end
  end
end
