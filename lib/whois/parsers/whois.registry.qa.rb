#--
# Ruby Whois
#
# An intelligent pure Ruby WHOIS client and parser.
#
# Copyright (c) 2009-2022 Simone Carletti <weppos@weppos.net>
#++


require_relative 'base_shared1'
require 'whois/scanners/whois.registry.qa'


module Whois
  class Parsers

    # Parser for the whois.registry.qa server.
    #
    # Current responses use the "Registrar", "Domain Status" and
    # "<Role> Name" lines; the legacy layout used "Registrar ID/Name",
    # "Status" and "<Role> Contact ID/Name/Email". Both are read.
    #
    # @see Whois::Parsers::Example
    #   The Example parser for the list of all available methods.
    #
    class WhoisRegistryQa < BaseShared1

      self.scanner = Scanners::WhoisRegistryQa


      # "Domain Status" carries the EPP status code followed by its ICANN URL.
      property_supported :status do
        Array.wrap(node("Status") || node("Domain Status")).map { |value| value.split.first }
      end

      property_supported :registered? do
        !available? && !status.empty? && !node("Domain Name").to_s.strip.empty?
      end


      property_supported :registrar do
        name = node("Registrar Name") || node("Registrar")
        Parser::Registrar.new(id: node("Registrar ID"), name: name, organization: name) if name.present?
      end


      private

      def build_contact(element, type)
        return super if node("#{element} Contact ID")

        node("#{element} Name") do |name|
          Parser::Contact.new(type: type, name: name) if name.present?
        end
      end

    end

  end
end
