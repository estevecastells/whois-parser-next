require_relative 'base_identity_digital'
module Whois
  class Parsers
    class WhoisNicRacing < BaseIdentityDigital
      self.scanner = Scanners::BaseIcannCompliant, { pattern_available: /^No Data Found\s*$/i }
    end
  end
end
