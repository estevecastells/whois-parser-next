require_relative 'base_identity_digital'
module Whois
  class Parsers
    class WhoisNicGal < BaseIdentityDigital
      self.scanner = Scanners::BaseIcannCompliant, { pattern_available: /^The queried object does not exist: no matching objects found\s*$/i }
    end
  end
end
