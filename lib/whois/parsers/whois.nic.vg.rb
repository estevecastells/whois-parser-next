# frozen_string_literal: true

require_relative 'whois.centralnic.com'

module Whois
  class Parsers
    # Parser for the current whois.nic.vg server.
    class WhoisNicVg < WhoisCentralnicCom
      property_supported :status do
        return :available if available?

        super()
      end
    end
  end
end
