#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require 'whois/scanners/whois.dns.hr.rb'


module Whois
  class Parsers

    # Parser for the whois.dns.hr server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisDnsHr < Base
      include Scanners::Scannable

      self.scanner = Scanners::WhoisDnsHr


      property_not_supported :disclaimer


      property_supported :domain do
        node("Domain Name") || node("domain")
      end

      property_not_supported :domain_id


      property_supported :status do
        if available?
          :available
        elsif node("Domain Name") || node("domain")
          :registered
        else
          :unknown
        end
      end

      property_supported :available? do
        !!node("status:available")
      end

      property_supported :registered? do
        status == :registered
      end


      property_not_supported :created_on

      property_not_supported :updated_on

      property_supported :expires_on do
        node("Registrar Registration Expiration Date") { |value| parse_time(value) } ||
          node("expires") { |value| parse_time(value) }
      end


      property_not_supported :registrar


      property_supported :registrant_contacts do
        if node("descr")
          node("descr") do |array|
            _, zip, city = array[2].match(/([\d\s]+) (.+)/).to_a
            Parser::Contact.new(
              :type         => Parser::Contact::TYPE_REGISTRANT,
              :id           => nil,
              :name         => array[0],
              :organization => nil,
              :address      => array[1],
              :city         => city,
              :zip          => zip,
              :state        => nil,
              :country      => nil,
              :phone        => nil,
              :fax          => nil,
              :email        => nil
            )
          end
        elsif node("Registrant Name")
          Parser::Contact.new(
            type: Parser::Contact::TYPE_REGISTRANT,
            name: node("Registrant Name"),
            address: node("Registrant Street"),
            city: node("Registrant City"),
            zip: node("Registrant Postal Code"),
            country_code: node("Registrant Country"),
            email: node("Registrant Email")
          )
        end
      end

      property_not_supported :admin_contacts

      property_not_supported :technical_contacts


      property_not_supported :nameservers

      def response_unavailable?
        body = content_for_scanner
        !body.match?(/^%ERROR:\s*no entries found\s*$/i) &&
          !body.match?(/^Domain Name:\s+\S+/i) &&
          !body.match?(/^domain:\s+\S+/i)
      end

    end

  end
end
