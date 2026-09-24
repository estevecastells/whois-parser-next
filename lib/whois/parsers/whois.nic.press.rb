require_relative 'base_identity_digital'
module Whois
  class Parsers
    class WhoisNicPress < BaseIdentityDigital
      self.scanner = Scanners::BaseIcannCompliant, { pattern_available: /^>>> Domain \S+ is available for registration\s*$/i }
    end
  end
end
