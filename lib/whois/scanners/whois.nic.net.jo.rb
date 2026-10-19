# frozen_string_literal: true

require_relative 'base_cocca2'

module Whois
  module Scanners
    class WhoisNicNetJo < BaseCocca2
      self.tokenizers += [:skip_jordan_absence]

      tokenizer :skip_jordan_absence do
        @input.skip(/^No match for domain "[^"\n]+"[ \t]*\n/i)
      end
    end
  end
end
