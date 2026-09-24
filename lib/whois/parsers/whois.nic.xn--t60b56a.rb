require_relative 'base_identity_digital'
module Whois
  class Parsers
    class WhoisNicXn_t60b56a < BaseIdentityDigital
      self.scanner = Scanners::BaseIcannCompliant, { pattern_available: /^No match for\s+"[^"]+"\.\s*$/i }
    end
  end
end
