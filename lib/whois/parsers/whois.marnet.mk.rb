# frozen_string_literal: true

require_relative 'base_whoisd'

module Whois
  class Parsers
    # Parser for the whois.marnet.mk server.
    class WhoisMarnetMk < BaseWhoisd
      property_supported :status do
        if available?
          :available
        elsif node('domain') && [node('registered'), node('registrar'), node('expire')].any?(&:present?)
          :registered
        else
          :unknown
        end
      end
    end
  end
end
