require_relative 'whois.centralnic.com'

module Whois
  class Parsers
    # Parser for the CentralNic WHOIS service used by .best.
    class WhoisNicBest < WhoisCentralnicCom
    end
  end
end
