#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_afilias'


module Whois
  class Parsers

    # Parser for the whois.afilias-grs.info server.
    class WhoisAfiliasGrsInfo < BaseAfilias

      self.scanner = Scanners::BaseAfilias, {
          pattern_disclaimer: /^Access to CCTLD WHOIS information is provided/,
      }

      # The live server appends registrar-referral text after the registry
      # record. The first update marker terminates the registry response and
      # is the stable portion this parser owns.
      def content
        super.sub(/\n>>> Last update of WHOIS database:.*\z/m, "\n")
      end

    end

  end
end
