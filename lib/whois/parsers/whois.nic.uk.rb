#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base'
require_relative 'registry_response_safety'


module Whois
  class Parsers

    # Parser for the whois.nic.uk server.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    #
    # @see http://www.nominet.org.uk/other/whois/detailedinstruct/
    #
    class WhoisNicUk < Base
      include RegistryResponseSafety

      DOMAIN_NAME_LINE = /^[ \t]*Domain name:[ \t]*(.*?)[ \t]*\r?$/i
      NO_MATCH_LINE = /^[ \t]*No match for "([^"]+)"\.[ \t]*\r?$/i
      NOT_REGISTERED_LINE = /^[ \t]*This domain name has not been registered\.[ \t]*\r?$/i
      REGISTRATION_STATUS_LINE = /\A[ \t]*Registration status:[ \t]*(.*?)[ \t]*\r?\n?\z/i
      REGISTRATION_SUPPORT_LINE = /^[ \t]*(?:Registered on|Expiry date|Last updated|Registrar):/i
      REGISTRATION_EVIDENCE_LINE = /^[ \t]*(?:Domain name|Registration status|Registered on|Expiry date|Last updated|Registrar|Name servers):/i
      REGISTRATION_STATUSES = {
        'registered until expiry date.' => :registered,
        'registration request being processed.' => :registered,
        'renewal request being processed.' => :registered,
        'no longer required' => :registered,
        'renewal required.' => :registered,
        'no registration status listed.' => :reserved,
      }.freeze

      # == Values for Status
      #
      # @see http://www.nominet.org.uk/registrars/systems/data/regstatus/
      # @see http://www.nominet.org.uk/registrants/maintain/renew/status/
      #
      property_supported :status do
        body = content_for_scanner
        absence_markers = body.lines.count do |line|
          line.match?(NO_MATCH_LINE) || line.match?(NOT_REGISTERED_LINE)
        end

        if absence_markers.positive?
          authoritative_absence?(body) ? :available : :unknown
        elsif invalid? && !registration_evidence?(body)
          :invalid
        else
          domains = domain_name_values(body)
          statuses = registration_status_values(body)
          if domains.length != 1 || !domains.first.downcase.end_with?('.uk') || statuses.length != 1
            :unknown
          else
            status = REGISTRATION_STATUSES[statuses.first.downcase]
            if status == :registered && !body.match?(REGISTRATION_SUPPORT_LINE)
              :unknown
            else
              status || :unknown
            end
          end
        end
      end

      property_supported :available? do
        status == :available
      end

      property_supported :registered? do
        status == :registered
      end


      property_supported :created_on do
        if content_for_scanner =~ /\s+Registered on:\s+(.+)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :updated_on do
        if content_for_scanner =~ /\s+Last updated:\s+(.+)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :expires_on do
        if content_for_scanner =~ /\s+Expiry date:\s+(.+)\n/
          parse_time(::Regexp.last_match(1))
        end
      end


      # @see http://www.nic.uk/other/whois/instruct/
      property_supported :registrar do
        if content_for_scanner =~ /Registrar:\n((.+\n)+)\n/
          content = ::Regexp.last_match(1).strip
          id = name = org = url = nil

          if content =~ /Tag =/
            name, id = (content =~ /(.+) \[Tag = (.+)\]/) && [::Regexp.last_match(1).strip, ::Regexp.last_match(2).strip]
            org, name = name.split(" t/a ")
            url = (content =~ /URL: (.+)/) && ::Regexp.last_match(1).strip
          elsif content =~ /This domain is registered directly with Nominet/
            name  = "Nominet"
            org   = "Nominet UK"
            url   = "http://www.nic.uk/"
          end

          Parser::Registrar.new(
            :id           => id,
            :name         => name || org,
            :organization => org,
            :url          => url
          )
        end
      end


      property_supported :registrant_contacts do
        if content_for_scanner =~ /Registrant's address:\n((.+\n)+)\n/
          lines = ::Regexp.last_match(1).split("\n").map(&:strip)
          address = lines[0..-5]
          city    = lines[-4]
          state   = lines[-3]
          zip     = lines[-2]
          country = lines[-1]

          Parser::Contact.new(
            :type => Parser::Contact::TYPE_REGISTRANT,
            :name => content_for_scanner[/Registrant:\n\s*(.+)\n/, 1],
            :address => address.join("\n"),
            :city => city,
            :state => state,
            :zip => zip,
            :country => country
          )
        end
      end


      property_supported :nameservers do
        if content_for_scanner =~ /Name servers:\n((.+\n)+)\n/
          ::Regexp.last_match(1).split("\n").reject { |value| value =~ /No name servers listed/ }.map do |line|
            name, ipv4, ipv6 = line.strip.split(/\s+/)
            Parser::Nameserver.new(:name => name, :ipv4 => ipv4, :ipv6 => ipv6)
          end
        end
      end


      # Checks whether the response has been throttled.
      #
      # @return [Boolean]
      #
      # @example
      #   The WHOIS query quota for 127.0.0.1 has been exceeded
      #   and will be replenished in 50 seconds.
      #
      def response_throttled?
        content_for_scanner.match?(/^[ \t]*The WHOIS query quota for .+ has been exceeded\b/i) ||
          RegistryResponseSafety.instance_method(:response_throttled?).bind_call(self)
      end

      def registration_status_values(body)
        lines = body.lines
        lines.each_with_index.filter_map do |line, index|
          match = REGISTRATION_STATUS_LINE.match(line)
          next unless match

          value = match[1].strip
          if value.empty?
            next_index = index + 1
            next_index += 1 while next_index < lines.length && lines[next_index].strip.empty?
            value = lines[next_index].to_s.strip
          end
          value unless value.empty?
        end
      end

      def domain_name_values(body)
        lines = body.lines
        lines.each_with_index.filter_map do |line, index|
          match = DOMAIN_NAME_LINE.match(line)
          next unless match

          value = match[1].strip
          if value.empty?
            next_index = index + 1
            next_index += 1 while next_index < lines.length && lines[next_index].strip.empty?
            value = lines[next_index].to_s.strip.split(/\s+/, 2).first.to_s
          end
          value unless value.empty?
        end
      end

      def authoritative_absence?(body)
        no_match = body.lines.filter_map { |line| NO_MATCH_LINE.match(line)&.captures&.first }
        not_registered = body.lines.count { |line| line.match?(NOT_REGISTERED_LINE) }
        no_match.length == 1 && no_match.first.downcase.end_with?('.uk') &&
          not_registered == 1 && !registration_evidence?(body) && !invalid?
      end

      def registration_evidence?(body)
        body.match?(REGISTRATION_EVIDENCE_LINE)
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
          !!(content_for_scanner =~ /This domain cannot be registered/)
        end
      end

      # NEWPROPERTY
      # def suspended?
      # end

    end

  end
end
