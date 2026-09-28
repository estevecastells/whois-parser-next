require_relative 'base_top1000_icann'

module Whois
  class Parsers
    # Parser for IANA's current .click WHOIS host, whois.registry.click.
    class WhoisRegistryClick < BaseTop1000Icann
    end
  end
end
