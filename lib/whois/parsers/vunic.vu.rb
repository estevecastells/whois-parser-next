require_relative 'whois.vunic.vu'

module Whois
  class Parsers
    # The whois gem identifies the live endpoint as `vunic.vu`, without a
    # `whois.` prefix. Keep the existing named parser and expose the loader
    # name required by Whois::Parser's host-based autoloading.
    class VunicVu < WhoisVunicVu
    end
  end
end
