# frozen_string_literal: true

require_relative 'whois.centralnic.com'

module Whois
  class Parsers
    # Parser for the current whois.nic.cat server.
    #
    # The current puntCAT service uses the CentralNic-style response layout,
    # but its absence response says "no matching objects found".
    class WhoisNicCat < WhoisCentralnicCom
      property_supported :status do
        return :available if available?

        super()
      end

      property_supported :available? do
        super() || content.match?(/The queried object does not exist:\s*no matching objects found/i)
      end
    end
  end
end
