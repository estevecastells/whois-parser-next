require_relative 'whois.nic.store'

module Whois
  class Parsers
    # The .ky registry uses the ICANN layout and Radix's exact availability
    # sentence.
    class WhoisKyregistryKy < WhoisNicStore
    end
  end
end
