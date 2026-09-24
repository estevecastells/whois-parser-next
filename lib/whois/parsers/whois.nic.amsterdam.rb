require_relative 'base_identity_digital'
module Whois
  class Parsers
    class WhoisNicAmsterdam < BaseIdentityDigital
      self.scanner = Scanners::BaseIcannCompliant, { pattern_available: /^Domain Status:\s*free\s*$/i }
    end
  end
end
