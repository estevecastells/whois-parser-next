#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_cocca2'


module Whois
  class Parsers

    # Parser for the whois.gg server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisGg < BaseCocca2

      property_supported :domain do
        if current_response? && content_for_scanner =~ /^Domain:\s*\n\s*(\S+)\s*$/
          ::Regexp.last_match(1)
        else
          super()
        end
      end

      property_supported :status do
        if content_for_scanner.strip == "NOT FOUND"
          :available
        elsif current_response?
          :registered
        else
          list = Array.wrap(node("Domain Status")).map(&:downcase)
          list.include?("available") ? :available : super()
        end
      end

      property_supported :created_on do
        if content_for_scanner.strip == "NOT FOUND"
          nil
        elsif content_for_scanner =~ /^\s*Registered on (\d{1,2})(?:st|nd|rd|th)\s+([A-Za-z]+)\s+(\d{4})/i
          parse_time("#{::Regexp.last_match(1)} #{::Regexp.last_match(2)} #{::Regexp.last_match(3)}")
        else
          super()
        end
      end

      property_supported :nameservers do
        current = content_for_scanner.scan(/^\s*ns(?:\d+)\.\S+\s*$/i).map(&:strip)
        if content_for_scanner.strip == "NOT FOUND"
          []
        elsif current.empty?
          super()
        else
          current.map { |name| Parser::Nameserver.new(name: name) }
        end
      end

      property_supported :domain_id do
        current_response? ? nil : super()
      end

      property_supported :updated_on do
        current_response? ? nil : super()
      end

      property_supported :expires_on do
        current_response? ? nil : super()
      end

      property_supported :registrar do
        if current_response?
          name = content_for_scanner[/^Registrar:\s*(.+)$/i, 1]
          name && Parser::Registrar.new(name: name.strip)
        else
          super()
        end
      end

      private

      def current_response?
        content_for_scanner.match?(/\ADomain:\s*\n|\ANOT FOUND\s*\z/i)
      end

    end

  end
end
