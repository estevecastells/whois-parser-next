require_relative 'base_identity_digital'
module Whois
  class Parsers
    class WhoisNicFrl < BaseIdentityDigital
      self.scanner = Scanners::BaseIcannCompliant, { pattern_available: /^The queried object does not exist: DOMAIN NOT FOUND\s*$/i }
    end
  end
end
