#--
# Ruby Whois
#++

require_relative 'whois.nic.cr'

module Whois
  class Parsers
    # The official LSNIC response uses NIC-style registration fields.
    class WhoisNicLs < WhoisNicCr
      property_supported :status do
        classify_ls_status
      end

      property_supported :available? do
        classify_ls_status == :available
      end

      private

      def classify_ls_status
        text = content_for_scanner
        domains = text.scan(/^domain:[ \t]*(\S+)[ \t]*$/i).flatten
        absent = text.scan(/^No record found for '([^']+)'\.[ \t]*$/i).flatten
        details = text.match?(/^(?:domain|registered|expire|nserver|registrar):/i)
        if absent.one? && valid_ls_domain?(absent.first) && !details
          :available
        elsif absent.empty? && domains.one? && valid_ls_domain?(domains.first) &&
            text.scan(/^registered:[ \t]*\d{2}\.\d{2}\.\d{4}(?:[ \t][^\r\n]*)?$/i).one? &&
            text.scan(/^expire:[ \t]*\d{2}\.\d{2}\.\d{4}[ \t]*$/i).one?
          :registered
        else
          :unknown
        end
      end

      def valid_ls_domain?(name)
        name.match?(/\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+ls\z/i)
      end
    end
  end
end
