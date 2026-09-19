require_relative 'whois.centralnic.com'

module Whois
  class Parsers
    # Parser for the CentralNic WHOIS service used by .art.
    class WhoisNicArt < WhoisCentralnicCom
    end
  end
end
