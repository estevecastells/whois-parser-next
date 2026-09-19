require_relative 'base'

module Whois
  module Scanners

    # Scanner for the whois.dns.hr record.
    class WhoisDnsHr < Base

      self.tokenizers += [
          :skip_empty_line,
          :scan_available,
          :skip_comment,
          :scan_keyvalue,
      ]


      tokenizer :scan_available do
        if @input.skip(/^%ERROR:\s*no entries found\s*\n/i)
          @ast["status:available"] = true
        end
      end

      tokenizer :skip_comment do
        @input.skip(/^%.*\n/)
      end

    end

  end
end
