require_relative 'whois.biz'
require_relative 'registry_response_safety'

module Whois
  class Parsers
    class WhoisDnrsVu < WhoisBiz
      include RegistryResponseSafety

      property_supported :status do
        text = content_for_scanner
        absence = text.scan(/^No Data Found[ \t]*\r?$/i)
        record = text.match?(/^(?:Domain Name|Registry Domain ID|Creation Date|Registry Expiry Date|Registrar|Domain Status|Name Server):[ \t]*\S/i)
        if absence.any?
          absence.one? && !record ? :available : :unknown
        else
          names = text.scan(/^Domain Name:[ \t]*([^\r\n]+)$/i).flatten.map(&:strip)
          details = text.match?(/^(?:Registry Domain ID|Creation Date|Registry Expiry Date|Registrar):[ \t]*\S/i)
          names.one? && names.first.match?(/\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+vu\z/i) && details ? :registered : :unknown
        end
      end

      property_supported(:available?) { status == :available }
      property_supported(:registered?) { status == :registered }
    end
  end
end
