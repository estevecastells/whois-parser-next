require_relative 'base_centralnic_icann'

module Whois
  class Parsers
    # The .дети registry uses the same CentralNic ICANN record shape, with
    # `DOMAIN NOT FOUND` as its authoritative absence marker.
    class WhoisNicXnD1acj3b < BaseCentralnicIcann
      self.scanner = Scanners::BaseIcannCompliant, {
        pattern_available: /^The queried object does not exist:\s+[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.xn--d1acj3b\s*$/i,
      }
    end

    const_set('WhoisNicXn_d1acj3b', WhoisNicXnD1acj3b)
  end
end
