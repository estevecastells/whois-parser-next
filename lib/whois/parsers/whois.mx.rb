#--
# Ruby Whois
#++

require_relative 'whois.nic.mx.rb'

module Whois
  class Parsers

    # The registry currently advertises whois.mx. Keep the existing parser
    # implementation shared with the historical whois.nic.mx hostname.
    class WhoisMx < WhoisNicMx
    end

  end
end
