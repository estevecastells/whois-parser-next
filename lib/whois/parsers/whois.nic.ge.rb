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

    # Parser for the whois.nic.ge server.
    #
    class WhoisNicGe < Base
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

      private

      def classify_status
        if registered_evidence?
          :registered
        elsif available_evidence?
          :available
        else
          :unknown
        end
      end

      def registered_evidence?
        registered_domain_names.one? && absence_domain_names.empty? && status_values == ['ok']
      end

      def available_evidence?
        absence_domain_names.one? && registered_domain_names.empty? && status_values.empty? &&
          !content_for_scanner.match?(/^[ \t]*Domain Name:/i)
      end

      def registered_domain_names
        content_for_scanner.scan(
          /^[ \t]*Domain Name:[ \t]*((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+ge)[ \t]*$/i
        ).flatten.map(&:downcase).uniq
      end

      def status_values
        content_for_scanner.scan(/^[ \t]*Domain Status:[ \t]*(.+?)[ \t]*$/i).flatten.map(&:downcase).uniq
      end

      def absence_domain_names
        content_for_scanner.scan(
          /^[ \t]*No match for "((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+ge)"\.[ \t]*$/i
        ).flatten.map(&:downcase).uniq
      end

    end

  end
end
