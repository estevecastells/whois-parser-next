require_relative 'base'

module Whois
  module Scanners

    # Scanner for the whois.fi record.
    class WhoisFi < Base

      self.tokenizers += [
          :skip_empty_line,
          :scan_available,
          :scan_disclaimer,
          :skip_section_header,
          :scan_keyvalue_normalized,
          :scan_reserved,
          :skip_lastupdate,
          :skip_copyright,
      ]


      tokenizer :scan_available do
        if @input.skip(/^Domain not found/)
          @ast["status:available"] = true
        end
      end

      tokenizer :scan_reserved do
        if @input.skip(/^Domain not available/)
          @ast["status:reserved"] = true
        end
      end

      tokenizer :skip_section_header do
        @input.skip(/^(Nameservers|DNSSEC|Holder|Registrar|Tech)\n/)
      end

      tokenizer :skip_lastupdate do
        @input.skip(/^>>> Last update of WHOIS database:.*\n/)
      end

      tokenizer :skip_copyright do
        @input.skip(/^Copyright \(c\) Finnish Transport and Communications Agency Traficom\n/)
      end

      tokenizer :scan_keyvalue_normalized do
        if @input.scan(/(.+?):(.*?)(\n|\z)/)
          key = @input[1].strip.sub(/\.+\z/, "").strip
          value = @input[2].strip
          @ast[key] = if @ast.key?(key)
                        Array.wrap(@ast[key]) << value
                      else
                        value
                      end
        end
      end

      tokenizer :scan_disclaimer do
        if @input.match?(/^More information/)
          @ast["field:disclaimer"] = @input.scan_until(/(.*)\n\n/).strip
        end
      end

    end

  end
end
