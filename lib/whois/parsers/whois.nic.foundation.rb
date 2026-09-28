require_relative 'base_icann_compliant'

module Whois
  class Parsers
    class WhoisNicFoundation < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^Domain not found\.[ \t]*$/i,
      }

    end
  end
end
