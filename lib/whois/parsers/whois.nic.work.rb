require_relative 'base_unsupported_registry'

module Whois
  class Parsers
    # The current endpoint returns reservation/unsupported notices rather
    # than a public registration record for .WORK.
    class WhoisNicWork < BaseUnsupportedRegistry
    end
  end
end
