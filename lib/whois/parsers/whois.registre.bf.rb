require_relative 'base_cocca2'
require_relative 'cocca_epp_status'

module Whois
  class Parsers
    class WhoisRegistreBf < BaseCocca2
      include CoccaEppStatus
      CURRENT_COCCA_SUFFIX = "bf".freeze

      property_supported(:status) { current_cocca_status || :unknown }
      property_supported(:available?) { status == :available }
      property_supported(:registered?) { status == :registered }
    end
  end
end
