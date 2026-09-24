#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require_relative 'registry_response_safety'
require 'whois/scanners/whois.cnnic.cn.rb'


module Whois
  class Parsers

    # Parser for the whois.cnnic.cn server.
    class WhoisCnnicCn < Base
      include RegistryResponseSafety
      include Scanners::Scannable

      self.scanner = Scanners::WhoisCnnicCn

      RESPONSE_MARKER = /(?:^No matching record\.?\s*$|^The domain you requested is prohibited\.?\s*$|^Sorry, The domain you requested is in the reserved list\.?\s*$|^Domain Name:\s*\S+)/i


      property_not_supported :disclaimer


      property_supported :domain do
        node("Domain Name", &:downcase)
      end

      property_supported :domain_id do
        node("ROID")
      end


      property_supported :status do
        return [] if available? || reserved?
        return :unknown unless recognized_response?

        statuses = Array.wrap node("Domain Status")
        if statuses.empty?
          :unknown
        else
          statuses
        end
      end

      property_supported :available? do
        return true if content_for_scanner.match?(/^No matching record\.?\s*$/i)
        return false unless recognized_response?

        !!node("status:available")
      end

      property_supported :registered? do
        status.is_a?(Array) && !status.empty? && registered_evidence?
      end


      property_supported :created_on do
        node("Registration Time") { |value| parse_time(value) }
      end

      property_not_supported :updated_on

      property_supported :expires_on do
        node("Expiration Time") { |value| parse_time(value) }
      end


      property_supported :registrar do
        node("Sponsoring Registrar") do |value|
          Parser::Registrar.new(
            :id   => value,
            :name => value
          )
        end
      end

      property_supported :registrant_contacts do
        build_contact("Registrant", Parser::Contact::TYPE_REGISTRANT)
      end

      property_supported :admin_contacts do
        build_contact("Administrative", Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_not_supported :technical_contacts


      property_supported :nameservers do
        Array.wrap(node("Name Server")).map do |name|
          Parser::Nameserver.new(name: name.downcase)
        end
      end


      # NEWPROPERTY
      def reserved?
        return true if content_for_scanner.match?(/^The domain you requested is prohibited\.?\s*$/i)
        return true if content_for_scanner.match?(/^Sorry, The domain you requested is in the reserved list\.?\s*$/i)
        return false unless recognized_response?

        !!node("status:reserved")
      end

      private

      def registered_evidence?
        !node("Domain Name").to_s.strip.empty? &&
          !Array.wrap(node("Domain Status")).empty?
      end

      def recognized_response?
        content_for_scanner.match?(RESPONSE_MARKER)
      end


      def build_contact(element, type)
        node("#{element}") do |value|
          Parser::Contact.new(
            :type         => type,
            :id           => node("#{element} ID"),
            :name         => value,
            :email        => node("#{element} Contact Email")
          )
        end
      end

    end
  end
end
