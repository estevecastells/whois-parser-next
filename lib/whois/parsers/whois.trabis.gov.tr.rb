require_relative 'base'
require_relative 'registry_response_safety'

module Whois
  class Parsers
    # Parser for the whois.trabis.gov.tr server.
    class WhoisTrabisGovTr < Base
      include RegistryResponseSafety

      HIDDEN = "Hidden upon user request".freeze
      EMAIL  = /[\w.+-]+@[\w-]+(?:\.[\w-]+)+/

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

      # The "** Registrant:" block runs until the first blank line. A fully
      # published block has eight lines: name, two address lines, "city,",
      # country, email, phone and fax. Each hidden field reads "Hidden upon user
      # request" and hidden blocks are shorter (a visible name plus four hidden
      # lines), so positional fields are read only from the eight-line layout.
      # The name is always the first line and the email is matched anywhere in
      # the block. A block with no visible field yields no contact.
      property_supported :registrant_contacts do
        block = content_for_scanner.slice(/^\*\* Registrant:\n((?:.+\n)+)/, 1)
        return [] unless block

        lines = block.lines.map(&:strip)
        value = ->(i) { (v = lines[i].to_s).empty? || v == "+" || v == HIDDEN ? nil : v }
        email = lines.find { |l| l.match?(EMAIL) }&.slice(EMAIL)
        name  = value.call(0)
        full  = lines.size == 8

        address = full ? [value.call(1), value.call(2)].compact.join("\n").presence : nil
        city    = full ? value.call(3)&.chomp(",")&.strip : nil
        country = full ? value.call(4) : nil
        phone   = full ? value.call(6) : nil
        fax     = full ? value.call(7) : nil
        return [] if [name, email, address, city, country, phone, fax].all?(&:nil?)

        [Parser::Contact.new(type: Parser::Contact::TYPE_REGISTRANT, name: name, address: address,
                             city: city, country: country, email: email, phone: phone, fax: fax)]
      end

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
