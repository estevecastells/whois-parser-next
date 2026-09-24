require_relative 'whois.cnnic.cn'

module Whois
  class Parsers
    # The registry publishes both `cwhois.cnnic.cn` and the historical
    # `whois.cnnic.cn` service name.  Keep both names on the same parser.
    class CwhoisCnnicCn < WhoisCnnicCn
    end
  end
end
