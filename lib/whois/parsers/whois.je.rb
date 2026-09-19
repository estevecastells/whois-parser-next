#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_cocca'


module Whois
  class Parsers

    # Parser for the whois.je server.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisJe < BaseCocca
      property_supported :domain do
        if (value = content_for_scanner[/\ADomain:\s*\n\s*(\S+)\s*$/i, 1])
          value.downcase
        else
          super()
        end
      end

      property_supported :status do
        if content_for_scanner.strip.match?(/\ANOT FOUND\z/i)
          :available
        elsif content_for_scanner.match?(/\ADomain:\s*\n\s*\S+/i)
          :registered
        else
          super()
        end
      end

      property_supported :available? do
        status == :available
      end

      property_supported :registered? do
        status == :registered
      end

      property_supported :created_on do
        if content_for_scanner =~ /^\s*Registered on (\d{1,2})(?:st|nd|rd|th)\s+([A-Za-z]+)\s+(\d{4})/i
          parse_time("#{::Regexp.last_match(1)} #{::Regexp.last_match(2)} #{::Regexp.last_match(3)}")
        else
          super()
        end
      end

      property_supported :registrar do
        if (value = content_for_scanner[%r{^Registrar:\s*(.+?)\s*\((https?://[^)]+)\)}i, 1])
          Parser::Registrar.new(name: value.strip)
        else
          super()
        end
      end

      property_supported :nameservers do
        current = content_for_scanner.scan(/^\s*(ns\d+\.\S+)\s*$/i).flatten
        if current.empty?
          super()
        else
          current.map { |name| Parser::Nameserver.new(name: name.downcase) }
        end
      end
    end

  end
end
