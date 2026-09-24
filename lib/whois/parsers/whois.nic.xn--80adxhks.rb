require_relative 'base_identity_digital'
module Whois
  class Parsers
    class WhoisNicXn_80adxhks < BaseIdentityDigital
      self.scanner = Scanners::BaseIcannCompliant, { pattern_available: /^[ \t]*Domain not found\.[ \t]*$/i }
    end
  end
end
