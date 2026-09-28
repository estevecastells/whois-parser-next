require_relative 'whois.biz'

module Whois
  class Parsers
    # The current IANA delegation points .biz to whois.nic.biz. Its record and
    # absence formats match the existing .biz registry parser.
    class WhoisNicBiz < WhoisBiz
      DOMAIN_LINE = /^Domain Name:[ \t]*(\S+)[ \t]*$/i
      REGISTERED_EVIDENCE = /^(?:Registry Domain ID|Creation Date|Updated Date|Registry Expiry Date|Registrar(?: IANA ID)?):[ \t]*\S/im
      ABSENCE_LINE = /^No Data Found[ \t]*\r?$/i
      RECORD_EVIDENCE = /^(?:Domain Name|Registry Domain ID|Creation Date|Updated Date|Registry Expiry Date|Registrar(?: IANA ID)?|Domain Status|Name Server):[ \t]*\S/im

      property_supported :status do
        body = content_for_scanner
        absence_count = body.lines.count { |line| line.match?(ABSENCE_LINE) }

        if absence_count.positive?
          absence_count == 1 && !body.match?(RECORD_EVIDENCE) ? :available : :unknown
        else
          domains = body.scan(DOMAIN_LINE).flatten
          if domains.length == 1 && domains.first.downcase.end_with?('.biz') && body.match?(REGISTERED_EVIDENCE)
            :registered
          else
            :unknown
          end
        end
      end

      property_supported :available? do
        status == :available
      end

      property_supported :registered? do
        status == :registered
      end
    end
  end
end
