#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#++

require_relative 'whois.domainregistry.ie.rb'

module Whois
  class Parsers

    # The current whois gem maps .ie to whois.iedr.ie. Preserve the parser
    # implementation shared with the registry's historical hostname.
    class WhoisIedrIe < WhoisDomainregistryIe
    end

  end
end
