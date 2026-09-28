require_relative 'base_unsupported_registry'

module Whois
  class Parsers
    # IANA currently lists RDAP only for .news. Keep this adapter only so a
    # legacy upstream WHOIS route fails explicitly instead of claiming status.
    class WhoisNicNews < BaseUnsupportedRegistry
    end
  end
end
