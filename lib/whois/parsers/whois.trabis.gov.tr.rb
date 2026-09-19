require_relative 'base'
require_relative 'registry_response_safety'

module Whois
  class Parsers
    # Parser for the whois.trabis.gov.tr server.
    class WhoisTrabisGovTr < Base
      include RegistryResponseSafety

      property_supported :domain do
        content_for_scanner.slice(/^\*\* Domain Name:\s+(.+)\n/, 1)
      end

      property_supported :status do
        if available?
          :available
        elsif domain
          :registered
        else
          :unknown
        end
      end

      property_supported :available? do
        !!(content_for_scanner =~ /^No match found for .+\n/)
      end

      property_supported :registered? do
        status == :registered
      end

      property_supported :created_on do
        if content_for_scanner =~ /^Created on\.+:\s+(.+)\.\n/
          parse_time(Regexp.last_match(1))
        end
      end

      property_supported :expires_on do
        if content_for_scanner =~ /^Expires on\.+:\s+(.+)\.\n/
          parse_time(Regexp.last_match(1))
        end
      end

      property_not_supported :updated_on
      property_not_supported :registrar
      property_not_supported :registrant_contacts
      property_not_supported :admin_contacts
      property_not_supported :technical_contacts

      property_supported :nameservers do
        section = content_for_scanner.slice(/\*\* Domain Servers:\n((?:.+\n)+?)\n/, 1)
        return [] unless section

        section.lines.map { |line| Parser::Nameserver.new(name: line.strip) }
      end
    end
  end
end
