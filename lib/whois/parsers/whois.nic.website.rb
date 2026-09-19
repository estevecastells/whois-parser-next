require_relative 'whois.nic.store'

module Whois
  class Parsers
    # Parser for the Radix WHOIS service used by .website.
    class WhoisNicWebsite < WhoisNicStore
    end
  end
end
