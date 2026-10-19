#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require_relative 'registry_response_safety'
require 'whois/scanners/whois.sx.rb'


module Whois
  class Parsers

    # Parser for the whois.sx server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisSx < Base
      include RegistryResponseSafety
      include Scanners::Scannable

      self.scanner = Scanners::WhoisSx


      property_supported :disclaimer do
        node("field:disclaimer")
      end


      property_supported :domain do
        (node("Domain Name") || node("Not found"))&.downcase
      end

      property_supported :domain_id do
        node("Domain ID")
      end


      property_supported :status do
        current = current_registry_status
        return current if current

        case (s = node("Domain Status", &:downcase))
        when "available"
          :available
        when "ok"
          :registered
        when "premium name"
          :unavailable
        else
          Whois::Parser.bug!(ParserError, "Unknown status `#{s}'.")
        end
      end

      property_supported :available? do
        status == :available
      end

      property_supported :registered? do
        status == :registered
      end


      property_supported :created_on do
        node("Creation Date") { |value| parse_time(value) }
      end

      property_supported :updated_on do
        node("Updated Date") { |value| parse_time(value) }
      end

      property_supported :expires_on do
        node("Registry Expiry Date") { |value| parse_time(value) }
      end


      property_supported :registrar do
        node("Sponsoring Registrar") do |value|
          Parser::Registrar.new(
              :name         => value
          )
        end
      end


      property_supported :registrant_contacts do
        build_contact("Registrant", Parser::Contact::TYPE_REGISTRANT)
      end

      property_supported :admin_contacts do
        build_contact("Admin", Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_supported :technical_contacts do
        build_contact("Tech", Parser::Contact::TYPE_TECHNICAL)
      end


      property_supported :nameservers do
        Array.wrap(node("Name Server")).map do |name|
          Parser::Nameserver.new(:name => name)
        end
      end


      # Keep the historical scanner for old fixtures, while recognizing the
      # current EPP record and exact missing reply before scanning legacy text.
      def current_registry_status
        names = content_for_scanner.scan(/^Domain Name:[ \t]*(.+)$/i).flatten.map(&:strip)
        absent = content_for_scanner.scan(/^Not found:[ \t]*(\S+)[ \t]*$/i).flatten
        return nil if absent.empty? && !content_for_scanner.match?(/^Registry Domain ID:/i)

        valid = ->(name) { name.match?(/\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.sx\z/i) }
        if absent.size == 1 && names.empty? && valid.call(absent.first) &&
            !content_for_scanner.match?(/^(?:Creation Date|Registry Domain ID|Domain Status):/i)
          return :available
        end
        return :unknown unless absent.empty? && names.size == 1 && valid.call(names.first)

        statuses = content_for_scanner.scan(/^Domain Status:[ \t]*(\S+)(?:[^\n]*)$/i).flatten
        dates = content_for_scanner.scan(/^Creation Date:[ \t]*(.+)$/i).flatten.map(&:strip)
        return :unknown unless dates.size == 1 && dates.first.match?(/\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\z/)
        Date.iso8601(dates.first[0, 10])
        Time.iso8601(dates.first)
        if statuses.any? && statuses.all? { |value| value.match?(/\A(?:ok|active|(?:client|server)(?:Delete|Transfer|Update|Renew)Prohibited)\z/) }
          :registered
        else
          :unknown
        end
      rescue ArgumentError
        :unknown
      end

      private

      def build_contact(element, type)
        node("#{element} ID") do |id|
          Parser::Contact.new(
              :type         => type,
              :id           => id,
              :name         => node("#{element} Name"),
              :organization => node("#{element} Organization"),
              :address      => node("#{element} Street"),
              :city => node("#{element} City"),
              :zip          => node("#{element} Postal Code"),
              :country      => node("#{element} Country"),
              :email        => node("#{element} Email")
          )
        end
      end

    end

  end
end
