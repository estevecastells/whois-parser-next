#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#++


require_relative 'base'


module Whois
  class Parsers

    # Parser for the whois.nic.site server.
    class WhoisNicSite < Base

      property_supported :domain do
        content_for_scanner[/^Domain Name:\s*(\S+)/, 1]&.downcase
      end

      property_supported :status do
        if available?
          :available
        elsif reserved?
          :reserved
        else
          :registered
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /^>>> Domain \S+ is available for registration$/)
      end

      property_supported :registered? do
        !available? && !reserved?
      end

      def reserved?
        !!(content_for_scanner =~ /^>>> Domain name is (?:registry )?(?:reserved|blocked)$/)
      end

    end

  end
end
