require_relative 'whois.audns.net.au'

module Whois
  class Parsers
    # Parser for the whois.auda.org.au server.
    class WhoisAudaOrgAu < WhoisAudnsNetAu
      property_supported :available? do
        super() || !!(content_for_scanner =~ /^Domain not found\.\n/)
      end
    end
  end
end
