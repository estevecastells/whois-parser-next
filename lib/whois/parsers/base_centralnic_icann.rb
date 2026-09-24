require_relative 'base_icann_compliant'

module Whois
  class Parsers
    # CentralNic registries that expose the ICANN key/value record shape.
    class BaseCentralnicIcann < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^The queried object does not exist:\s+DOMAIN NOT FOUND\s*$/i,
      }
    end
  end
end
