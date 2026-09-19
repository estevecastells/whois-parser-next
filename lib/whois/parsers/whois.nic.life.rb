require_relative 'base_unsupported_registry'

module Whois
  class Parsers
    # Identity Digital currently returns an explicit unsupported-TLD response
    # for this host. Keep it unavailable until a registry record is observed.
    class WhoisNicLife < BaseUnsupportedRegistry
    end
  end
end
