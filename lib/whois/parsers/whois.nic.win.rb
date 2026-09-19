require_relative 'whois.nic.design'

module Whois
  class Parsers
    # The current .win endpoint uses the same CentralNic/MarkMonitor layout
    # as .design, including the `No Data Found` absence response.
    class WhoisNicWin < WhoisNicDesign
    end
  end
end
