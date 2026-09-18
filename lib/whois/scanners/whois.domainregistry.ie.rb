require_relative 'base'

module Whois
  module Scanners

    # Scanner for the whois.domainregistry.ie server.
    class WhoisDomainregistryIe < Base

      self.tokenizers += [
          :skip_empty_line,
          :scan_disclaimer,
          :scan_contact,
          :scan_available,
          :scan_keyvalue,
          :skip_application_pending,
          :skip_comment,
      ]

      tokenizer :scan_available do
        if @input.skip(/^% Not Registered - .+\n/) || @input.skip(/^Not found: .+\n/)
          @ast["status:available"] = true
        end
      end

      tokenizer :skip_comment do
        @input.skip(/^%.*\n/)
      end

      tokenizer :scan_disclaimer do
        if @input.match?(/^% Rights restricted by copyright/)
          @ast["field:disclaimer"] = _scan_lines_to_array(/^%(.+)\n/).join("\n")
        end
      end

      tokenizer :scan_contact do
        if @input.match?(/^person:/)
          lines = _scan_lines_to_hash(/(.+?):(.*?)\n/)
          @ast["field:#{lines['nic-hdl']}"] = lines
        end
      end

      tokenizer :skip_application_pending do
        if @input.match?(/^% Application Pending/)
          _scan_lines_to_array(/^%(.+)\n/)
          @ast["status:pending"] = true
        end
      end

    end
  end
end
