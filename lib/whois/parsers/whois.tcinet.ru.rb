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

    # Parser for the whois.tcinet.ru server.
    #
    # @note This parser is just a stub and provides only a few basic methods
    #   to check for domain availability and get domain status.
    #   Please consider to contribute implementing missing methods.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisTcinetRu < Base
      include RegistryResponseSafety

      DOMAIN_PATTERN = /\A(?:[[:alnum:]](?:[[:alnum:]-]{0,61}[[:alnum:]])?\.)+[[:alnum:]](?:[[:alnum:]-]{0,61}[[:alnum:]])?\z/i
      KNOWN_STATES = %w[REGISTERED DELEGATED NOT\ DELEGATED VERIFIED UNVERIFIED].freeze

      property_supported :domain do
        domain_value&.downcase
      end

      property_not_supported :domain_id


      property_supported :status do
        case classify_status
        when :registered
          state_values
        when :available
          []
        else
          :unknown
        end
      end

      property_supported :available? do
        classify_status == :available
      end

      property_supported :registered? do
        classify_status == :registered
      end


      property_supported :created_on do
        if content_for_scanner =~ /created:\s+(.*)\n/
          parse_time(::Regexp.last_match(1))
        end
      end

      property_not_supported :updated_on

      property_supported :expires_on do
        if content_for_scanner =~ /paid-till:\s+(.*)\n/
          parse_time(::Regexp.last_match(1))
        end
      end


      property_supported :registrar do
        if content_for_scanner =~ /registrar:\s+(.*)\n/
          Parser::Registrar.new(
              :id => ::Regexp.last_match(1)
          )
        end
      end


      property_supported :admin_contacts do
        url   = content_for_scanner[/admin-contact:\s+(.+)\n/, 1]
        email = content_for_scanner[/e-mail:\s+(.+)\n/, 1]
        contact = if url or email
                    Parser::Contact.new(
                      :type         => Parser::Contact::TYPE_ADMINISTRATIVE,
                      :url          => url,
                      :email        => email,
                      :name         => content_for_scanner[/person:\s+(.+)\n/, 1],
                      :organization => content_for_scanner[/org:\s+(.+)\n/, 1],
                      :phone        => content_for_scanner[/phone:\s+(.+)\n/, 1],
                      :fax          => content_for_scanner[/fax-no:\s+(.+)\n/, 1]
                    )
                  end
        Array.wrap(contact)
      end

      property_not_supported :registrant_contacts

      property_not_supported :technical_contacts


      # Nameservers are listed in the following formats:
      #
      #   nserver:     ns.masterhost.ru.
      #   nserver:     ns.masterhost.ru. 217.16.20.30
      #
      property_supported :nameservers do
        content_for_scanner.scan(/nserver:\s+(.+)\n/).flatten.map do |line|
          name, ipv4 = line.split(/\s+/)
          Parser::Nameserver.new(:name => name.chomp("."), :ipv4 => ipv4)
        end
      end

      def response_unavailable?
        super || content_for_scanner.match?(/^\s*access denied\b/i)
      end

      def response_throttled?
        super || content_for_scanner.match?(/^\s*too many requests\b/i)
      end


      private

      def classify_status
        cached_properties_fetch(:classified_status) do
          response = content_for_scanner
          domains = domain_lines
          state_rows = state_lines
          states = state_values
          normalized_states = states.map(&:upcase)
          valid_states = states.any? && normalized_states.all? { |state| KNOWN_STATES.include?(state) }
          conflicting_delegation = normalized_states.include?("DELEGATED") &&
            normalized_states.include?("NOT DELEGATED")
          conflicting_verification = normalized_states.include?("VERIFIED") &&
            normalized_states.include?("UNVERIFIED")
          safe_response = !response_unavailable? && !response_throttled?
          absence_count = response.lines.count do |line|
            line.chomp.match?(/\ANo entries found for the selected source\(s\)\.[ \t]*\z/i)
          end

          if safe_response && absence_count == 1 && domains.empty? && state_rows.empty?
            :available
          elsif safe_response && domains.one? && domain_value && state_rows.one? &&
              normalized_states.include?("REGISTERED") && valid_states &&
              !conflicting_delegation && !conflicting_verification && absence_count.zero?
            :registered
          else
            :unknown
          end
        end
      end

      def domain_lines
        content_for_scanner.lines.filter_map do |line|
          line.chomp.match(/\Adomain:[ \t]*(.*?)[ \t]*\z/i)&.[](1)
        end
      end

      def domain_value
        domains = domain_lines
        return unless domains.one? && domains.first.match?(DOMAIN_PATTERN)

        domains.first
      end

      def state_lines
        content_for_scanner.lines.filter_map do |line|
          line.chomp.match(/\Astate:[ \t]*(.*?)[ \t]*\z/i)&.[](1)
        end
      end

      def state_values
        rows = state_lines
        return [] unless rows.one?

        values = rows.first.split(",", -1).map(&:strip)
        return [] if values.any?(&:empty?)

        values
      end

    end

  end
end
