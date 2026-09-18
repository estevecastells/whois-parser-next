require_relative 'base_icann_compliant'

module Whois
  class Parsers

    class WhoisNicLink < BaseIcannCompliant
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^>>> Domain .+ is available for registration\n/,
      }
    end

  end
end
