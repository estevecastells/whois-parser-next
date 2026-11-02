module Whois
  module Scanners

    class Base

      class_attribute :tokenizers
      self.tokenizers = []

      # Consecutive tokens allowed to succeed without consuming input.
      MAX_IDLE_TOKENS = 100

      def self.tokenizer(name, &block)
        define_method(name, &block)
      end


      attr_reader :settings

      def initialize(settings = nil)
        @settings = settings || {}
      end

      def parse(content)
        # The temporary store.
        # Scanners may use this to store pointers, states or other flags.
        @tmp = {}

        # A super-simple AST store.
        @ast = {}

        @input = StringScanner.new(content)
        idle = 0
        until @input.eos?
          position = @input.pos
          tokenize
          if @input.pos == position
            # Some tokenizers succeed once without consuming input to change
            # state (e.g. close a section) for the next one. One that keeps
            # succeeding in place loops forever, e.g. a disclaimer header matched
            # by lookahead in a reply truncated before its final newline.
            idle += 1
            unexpected_token if idle > MAX_IDLE_TOKENS
          else
            idle = 0
          end
        end

        @ast
      end


      tokenizer :skip_empty_line do
        @input.skip(/^\n/)
      end

      tokenizer :skip_blank_line do
        @input.skip(/^\s*\n/)
      end

      tokenizer :skip_newline do
        @input.skip(/\n/)
      end

      # Scan a key/value pair and stores the result in the current target.
      #  target is the global @ast if no '_section' is set, else '_section' is used.
      tokenizer :scan_keyvalue do
        if @input.scan(/(.+?):(.*?)(\n|\z)/)
          key, value = @input[1].strip, @input[2].strip
          target = @tmp['_section'] ? (@ast[@tmp['_section']] ||= {}) : @ast

          if target[key].nil?
            target[key] = value
          else
            target[key] = Array.wrap(target[key])
            target[key] << value
          end
        end
      end

      protected

      def _scan_lines_to_array(pattern)
        results = []
        while @input.scan(pattern)
          @input[1].strip
          results << @input[1].strip
        end
        results
      end

      def _scan_lines_to_hash(pattern)
        results = {}
        results.merge! @input[1].strip => @input[2].strip while @input.scan(pattern)
        results
      end

      def _scan_keyvalues(pattern)
        results = []
        while @input.scan(/(.+?):(.*?)\n/)
          key, value = @input[1].strip, @input[2].strip
          if results[key].nil?
            results[key] = value
          else
            results[key] = Array.wrap(results[key])
            results[key] << value
          end
        end
      end


      private

      def tokenize
        tokenizers.each do |tokenizer|
          return if send(tokenizer)
        end
        unexpected_token
      end

      def unexpected_token
        error!("Unexpected token")
      end

      def error!(message)
        raise ParserError, "#{message}: #{@input.peek(@input.string.length)}"
      end

    end

  end
end
