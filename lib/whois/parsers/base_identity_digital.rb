require_relative 'base_icann_compliant'

module Whois
  class Parsers
    # Shared ICANN key/value parser for Identity Digital registries.
    #
    # Individual registries differ only in the authoritative absence marker;
    # host-specific subclasses keep those markers explicit.
    class BaseIdentityDigital < BaseIcannCompliant
    end
  end
end
