require_relative 'base_unsupported_registry'

module Whois
  class Parsers
    # Identity Digital's current .chat port-43 endpoint explicitly refuses
    # the TLD. Keep that response unavailable rather than inferring a status.
    class WhoisNicChat < BaseUnsupportedRegistry
    end
  end
end
