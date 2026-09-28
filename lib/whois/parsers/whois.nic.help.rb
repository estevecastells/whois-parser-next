require_relative 'base_identity_digital'

module Whois
  class Parsers
    # CentralNic's .HELP registry endpoint uses its exact no-object marker.
    class WhoisNicHelp < BaseIdentityDigital
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^The queried object does not exist: DOMAIN NOT FOUND\s*$/i,
      }
    end
  end
end
