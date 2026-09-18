#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#++


require_relative 'whois.centralnic.com'


module Whois
  class Parsers

    # Parser for the whois.registry.co server.
    class WhoisRegistryCo < WhoisCentralnicCom
    end

  end
end
