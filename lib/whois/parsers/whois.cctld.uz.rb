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

    # Parser for the whois.cctld.uz server.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisCctldUz < Base
      include RegistryResponseSafety

      property_supported :status do
        classify_status
      end

      property_supported :available? do
        classify_status == :available
      end

      property_supported :registered? do
        classify_status == :registered
      end


      property_supported :created_on do
        if content_for_scanner =~ /Creation Date:(.+)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :updated_on do
        if content_for_scanner =~ /Updated Date:(.+)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_supported :expires_on do
        if content_for_scanner =~ /Expiration Date:\s+(.+)\n/
          parse_time(::Regexp.last_match(1))
        end
      end


      property_supported :nameservers do
        if content_for_scanner =~ /Domain servers in listed order:\n((.+\n)+)\n/
          ::Regexp.last_match(1).split("\n").map do |name|
            Parser::Nameserver.new(:name => name.strip.chomp("."))
          end
        end
      end

      private

      def classify_status
        return :unknown if absence_conflicts_with_record?

        evidence = []
        evidence << :registered if registered_evidence?
        evidence << :reserved if reserved_evidence?
        evidence << :available if available_evidence?
        evidence.one? ? evidence.first : :unknown
      end

      def absence_conflicts_with_record?
        return false unless absence_domain_names.any?

        domain_names.any? || status_values.any? || content_for_scanner.match?(/^[ \t]*Domain Name:/i)
      end

      def registered_evidence?
        domain_names.one? && status_values == ["active"]
      end

      def reserved_evidence?
        domain_names.one? && status_values == ["reserved"]
      end

      def available_evidence?
        absence_domain_names.one? && status_values.empty? &&
          !content_for_scanner.match?(/^[ \t]*Domain Name:/i)
      end

      def domain_names
        content_for_scanner.scan(
          /^[ \t]*Domain Name:[ \t]*((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+uz)[ \t]*$/i
        ).flatten.map(&:downcase).uniq
      end

      def status_values
        content_for_scanner.scan(/^[ \t]*Status:[ \t]*([a-z]+)[ \t]*$/i).flatten.map(&:downcase).uniq
      end

      def absence_domain_names
        content_for_scanner.scan(
          /^[ \t]*Sorry, but domain:[ \t]*"((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+uz)", not found in database[ \t]*$/i
        ).flatten.map(&:downcase).uniq
      end

    end

  end
end
