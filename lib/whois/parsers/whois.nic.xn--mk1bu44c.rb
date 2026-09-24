require_relative 'base_top1000_icann'

module Whois
  class Parsers
    # Host-to-parser conversion preserves the punycode separator.
    # rubocop:disable-next Naming/ClassAndModuleCamelCase
    class WhoisNicXn_mk1bu44c < BaseTop1000Icann
      property_supported :available? do
        super() || !!(content_for_scanner =~ /^No match for "[^"]+"\.\s*$/i)
      end
    end
  end
end
