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

    # Parser for the whois.nic.ag server.
    class WhoisNicAg < BaseAfilias

      # Current .ag responses begin directly with key/value fields and append
      # a long policy footer after the registry's update marker. Avoid the
      # legacy disclaimer heuristic and parse only the registry record.
      self.scanner = Scanners::BaseAfilias, {
          pattern_disclaimer: /^Access to CCTLD WHOIS information is provided/,
      }

      def content
        super.sub(/\n>>> Last update of WHOIS database:.*\z/m, "\n")
      end

    end

  end
end
