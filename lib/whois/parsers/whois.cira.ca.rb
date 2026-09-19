#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require 'whois/scanners/whois.cira.ca.rb'


module Whois
  class Parsers

    # Parser for the whois.cira.ca server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisCiraCa < Base
      include Scanners::Scannable

      self.scanner = Scanners::WhoisCiraCa


      property_supported :disclaimer do
        node("field:disclaimer")
      end


      property_supported :domain do
        node("Domain name") || node("Domain Name")
      end

      property_not_supported :domain_id


      property_supported :status do
        status_value = node("Domain status") || node("Domain Status")

        if status_value
          case Array.wrap(status_value).map { |value| value.to_s.downcase.sub(%r{\s+https?://.*\z}, "") }
          when ["registered"]
            :registered
          when ["redemption"]
            :registered
          when ["auto-renew grace"]
            :registered
          when ["to be released"]
            :registered
          when ["pending delete"]
            :registered
          when ["available"]
            :available
          when ["unavailable"]
            :invalid
          else
            epp_statuses = Array.wrap(status_value).map { |value| value.to_s.downcase.sub(%r{\s+https?://.*\z}, "") }
            if epp_statuses.all? { |value| value.match?(/\A(?:client|server)(?:delete|transfer|update|renew)prohibited\z/) }
              :registered
            else
              Whois::Parser.bug!(ParserError, "Unknown status `#{epp_statuses.join(', ')}'.")
            end
          end
        elsif content_for_scanner =~ /^Not found:\s+/i
          :available
        elsif content_for_scanner =~ /Domain status:\s+(.+?)\n/
          case node("Domain status", &:downcase)
          when "registered"
            :registered
          when "redemption"
            :registered
          when "auto-renew grace"
            :registered
          when "to be released"
            :registered
          when "pending delete"
            :registered
          when "available"
            :available
          when "unavailable"
            :invalid
          else
            Whois::Parser.bug!(ParserError, "Unknown status `#{::Regexp.last_match(1)}'.")
          end
        else
          Whois::Parser.bug!(ParserError, "Unable to parse status.")
        end
      end

      property_supported :available? do
        status == :available
      end

      property_supported :registered? do
        status == :registered
      end


      property_supported :created_on do
        value = node("Creation date") || node("Creation Date")
        parse_time(value) if value
      end

      property_supported :updated_on do
        value = node("Updated date") || node("Updated Date")
        parse_time(value) if value
      end

      property_supported :expires_on do
        value = node("Expiry date") || node("Registry Expiry Date")
        parse_time(value) if value
      end


      property_supported :registrar do
        node("Registrar") do |value|
          if value.is_a?(Hash)
            Parser::Registrar.new(
              id:           value["Number"],
              name:         value["Name"],
              organization: value["Name"]
            )
          else
            Parser::Registrar.new(name: value, organization: value)
          end
        end
      end


      property_supported :registrant_contacts do
        build_contact("Registrant", Parser::Contact::TYPE_REGISTRANT)
      end

      property_supported :admin_contacts do
        build_contact("Administrative contact", Parser::Contact::TYPE_ADMINISTRATIVE)
      end

      property_supported :technical_contacts do
        build_contact("Technical contact", Parser::Contact::TYPE_TECHNICAL)
      end


      property_supported :nameservers do
        Array.wrap(node("nserver") || node("Name Server") || node("field:nameservers")).map do |line|
          name, ipv4 = line.split(/\s+/)
          Parser::Nameserver.new(:name => name, :ipv4 => ipv4)
        end
      end


      # Nameservers are listed in the following formats:
      #
      #   ns1.google.com
      #   ns2.google.com
      #
      #   ns1.google.com  216.239.32.10
      #   ns2.google.com  216.239.34.10
      #
      property_supported :nameservers do
        Array.wrap(node("field:nameservers") || node("Name Server") || node("nserver")).map do |line|
          name, ipv4 = line.strip.split(/\s+/)
          Parser::Nameserver.new(:name => name, :ipv4 => ipv4)
        end
      end


      # Attempts to detect and returns the version.
      #
      # TODO: This is very empiric.
      #       Use the available status in combination with the creation date label.
      #
      # NEWPROPERTY
      def version
        cached_properties_fetch :version do
          version = if content_for_scanner =~ /^% \(c\) (.+?) Canadian Internet Registration Authority/
                      case ::Regexp.last_match(1)
                      when "2007" then "1"
                      when "2010" then "2"
                      end
                    end
          version || Whois::Parser.bug!(ParserError, "Unable to detect version.")
        end
      end

      # NEWPROPERTY
      def valid?
        cached_properties_fetch(:valid?) do
          !invalid?
        end
      end

      # NEWPROPERTY
      def invalid?
        cached_properties_fetch(:invalid?) do
          status == :invalid
        end
      end


      private

      def build_contact(element, type)
        node(element) do |hash|
          Parser::Contact.new(
            :type         => type,
            :id           => nil,
            :name         => hash["Name"],
            :organization => nil,
            :address      => hash["Postal address"],
            :city         => nil,
            :zip          => nil,
            :state        => nil,
            :country      => nil,
            :phone        => hash["Phone"],
            :fax          => hash["Fax"],
            :email        => hash["Email"]
          )
        end
      end

    end

  end
end
