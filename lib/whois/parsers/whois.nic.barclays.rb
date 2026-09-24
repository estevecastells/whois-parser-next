require_relative 'base_identity_digital'
module Whois
  class Parsers
    class WhoisNicBarclays < BaseIdentityDigital
      self.scanner = Scanners::BaseIcannCompliant, { pattern_available: /^Domain not found\.\s*$/i }
    end
  end
end
