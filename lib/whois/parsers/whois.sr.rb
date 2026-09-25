require_relative 'base_top1000_icann'

module Whois
  class Parsers
    # Parser for the IANA-listed WHOIS server for .SR.
    #
    # IANA's delegation record and current server responses were checked on
    # 2026-09-25. The generated-name response uses an exact Message marker;
    # other incomplete responses must remain unknown.
    class WhoisSr < BaseTop1000Icann
      property_supported :domain do
        node("Domain", &:downcase)
      end

      property_supported :status do
        if reserved?
          :reserved
        elsif available?
          :available
        elsif !node("Domain").to_s.strip.empty? &&
              node("Status").to_s.casecmp("active").zero? &&
              !node("Creation Date").to_s.strip.empty?
          :registered
        else
          :unknown
        end
      end

      property_supported :available? do
        content_for_scanner.match?(/^Message: No Object Found\s*$/i)
      end

      property_supported :registered? do
        status == :registered
      end

      property_supported :nameservers do
        Array.wrap(node("Name server")).reject(&:empty?).map do |name|
          Parser::Nameserver.new(name: name.downcase)
        end
      end
    end
  end
end
