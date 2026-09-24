require_relative 'base_identity_digital'
module Whois
  class Parsers
    class WhoisGtldKnetCn < BaseIdentityDigital
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^The queried object does not exist:\s+[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+\s*$/i,
      }
    end
  end
end
