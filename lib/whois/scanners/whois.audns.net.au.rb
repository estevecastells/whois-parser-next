require_relative 'base'

module Whois
  module Scanners

    # Scanner for the whois.audns.net.au record.
    class WhoisAudnsNetAu < Base

      self.tokenizers += [
          :skip_empty_line,
          :scan_available,
          :skip_lastupdate,
          :scan_keyvalue,
      ]


      tokenizer :scan_available do
        if @input.skip(/^(No Data Found|Domain not found\.)\n/)
          @ast["status:available"] = true
        end
      end

      tokenizer :skip_lastupdate do
        if @input.skip(/^>>> Last update of WHOIS database:.*\n/)
          @input.terminate
        end
      end

    end

  end
end
