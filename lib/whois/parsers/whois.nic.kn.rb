require_relative 'base_icann_compliant'
require_relative 'cocca_epp_status'

module Whois
  class Parsers
    class WhoisNicKn < BaseIcannCompliant
      include CoccaEppStatus
      CURRENT_COCCA_SUFFIX = "kn".freeze

      property_supported(:status) { current_cocca_status || super() }
      property_supported :available? do
        current = current_cocca_status
        current.nil? ? super() : current == :available
      end
    end
  end
end
