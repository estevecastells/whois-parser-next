require_relative 'base'

module Whois
  module Scanners

    class BaseCocca2 < Base

      self.tokenizers += [
          :skip_empty_line,
          :scan_disclaimer,
          :skip_lastupdate,
          :skip_token_additionalsection,
          :skip_comment,
          :skip_no_object,
          :skip_footer,
          :scan_keyvalue,
      ]


      DISCLAIMER_MATCHES = [
        "TERMS OF USE:", # global
        "Terminos de Uso:", # whois.nic.hn
        "Queda absolutamente prohibido su uso", # current whois.nic.hn footer
        "The data in the WHOIS database of Meridian", # whois.meridiantld.net
        "This information is provided", # whois.gg
      ]

      tokenizer :scan_disclaimer do
        if @input.match?(/^#{DISCLAIMER_MATCHES.join('|')}/)
          @ast["field:disclaimer"] = @input.scan_until(/>>>/) ||
                                     # special handler for whois.nic.cx exception
                                     @input.scan_until(/\Z/)
        end
      end

      tokenizer :skip_lastupdate do
        @input.skip(/>>>(.+?)<<<\n/)
      end

      tokenizer :skip_token_additionalsection do
        @input.skip(/Additional Section\n/)
      end

      tokenizer :skip_comment do
        @input.skip(/^%.*\n/)
      end

      tokenizer :skip_no_object do
        @input.skip(/^The queried object does not exist: No Object Found\n/i)
      end

      tokenizer :skip_footer do
        @input.skip(/^For more information on domain status codes,.*\n/i)
      end

    end

  end
end
