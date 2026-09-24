require_relative 'base_identity_digital'

module Whois
  class Parsers
    # Identity Digital key/value records with the Ryce registry's short
    # `Available` absence response.
    class WhoisRyceRspCom < BaseIdentityDigital
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^Available\s*$/i,
      }
    end
  end
end
