require_relative 'base_shared1'

module Whois
  module Scanners

    # Scanner for the whois.registry.qa records.
    class WhoisRegistryQa < BaseShared1

      self.tokenizers = [:skip_head, :skip_end] + tokenizers


      # Current responses open with the instructions of the registry's web
      # lookup form.
      tokenizer :skip_head do
        @input.skip(/^Welcome to Qatar Domains Registry WHOIS Lookup\n(?:.*\n)*?Type the word you see into the verification box to proceed\.\n/)
      end

      # The status code reference ends the record; the copyright, terms of use
      # and query limit notice follow it.
      tokenizer :skip_end do
        if @input.check(/^For more information on Whois status codes, please visit /)
          @input.terminate
        end
      end

    end

  end
end
