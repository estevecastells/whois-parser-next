require_relative 'base_unsupported_registry'

module Whois
  class Parsers
    # Identity Digital does not expose .DELIVERY through this WHOIS endpoint.
    class WhoisNicDelivery < BaseUnsupportedRegistry
    end
  end
end
