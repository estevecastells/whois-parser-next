require_relative 'base_top1000_icann'

module Whois
  class Parsers
    # Beijing Tele-info serves both .在线 and .yun with ICANN-style records.
    class WhoisTeleinfoCn < BaseTop1000Icann
      property_supported :domain do
        content_for_scanner[/^Domain Name:\s*(\S+)/i, 1]&.downcase
      end

      property_supported :available? do
        super() || !!(content_for_scanner =~ /^No matching record\.\s*$/i)
      end
    end
  end
end
