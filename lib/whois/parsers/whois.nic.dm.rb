#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_shared3'


module Whois
  class Parsers

    # Parser for the whois.nic.dm server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisNicDm < BaseShared3
      # Tucows appends a long privacy notice after the registry fields. The
      # notice is not part of the record and otherwise trips the strict
      # shared scanner on current responses.
      def content
        super.to_s
             .split(/\nThe WHOIS information provided in this page has been redacted\b/, 2).first
             .split("\nURL of the ICANN RDDS Inaccuracy Complaint Form:", 2).first
      end

      # The registry returns this policy response for names it blocks. It is
      # not evidence that the name is available or registered.
      def response_unavailable?
        super || content_for_scanner.match?(/^>>> This name is not available for registration:/i)
      end
    end

  end
end
