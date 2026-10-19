# frozen_string_literal: true

require 'cgi'
require 'strscan'
require_relative 'base'
require_relative 'registry_response_safety'

module Whois
  class Parsers
    # The registry's per-domain public web WHOIS, observed 2026-10-19.
    # Inspect only its result heading/alert, never navigation or script text.
    class WwwGt < Base
      include RegistryResponseSafety

      property_supported(:status) { web_result[:status] }
      property_supported(:domain) { web_result[:domain] }
      property_supported(:registered?) { status == :registered }
      property_supported(:available?) { status == :available }

      def response_unavailable?
        super || content_for_scanner.match?(/<cap-widget\b|\bclass=["']g-recaptcha["']|cf-chl-/i)
      end

      private

      def web_result
        @web_result ||= classify_web_result
      end

      def classify_web_result
        blocks = result_blocks
        return { status: :unknown } unless blocks

        candidates = blocks.filter_map do |kind, text|
          text = CGI.unescapeHTML(text.gsub('&aacute;', 'á').gsub('&Aacute;', 'Á')).gsub(/[ \t\r\n]+/, ' ').strip
          if kind == 'h3' && (match = /\A(\S+)\. ACTIVO\z/i.match(text))
            [match[1].downcase, :registered]
          elsif kind == 'div' && (match = /\A(\S+)\. no está registrado \.\z/i.match(text))
            [match[1].downcase, :available]
          end
        end
        return { status: :unknown } unless candidates.size == 1

        name, state = candidates.first
        return { status: :unknown } unless name.bytesize <= 253 &&
          name.match?(/\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+gt\z/)

        { domain: name, status: state }
      end

      # One forward scan, including malformed tags. Limit each tag before
      # inspecting attributes and skip scripts, styles and comments entirely.
      def result_blocks
        input = StringScanner.new(content_for_scanner)
        blocks = []
        active = nil
        depth = 0
        text = +''
        until input.eos?
          chunk = input.scan_until(/</)
          unless chunk
            text << input.rest if active
            input.terminate
            break
          end
          text << chunk[0...-1] if active
          if input.peek(3) == '!--'
            return nil unless input.scan_until(/-->/)
            next
          end
          tag = input.scan_until(/>/)
          return nil unless tag && tag.bytesize <= 16_384
          match = /\A[ \t]*(\/?)[ \t]*([a-z0-9]+)/i.match(tag)
          next unless match
          closing = match[1] == '/'
          name = match[2].downcase
          if !closing && %w[script style].include?(name)
            return nil if active
            return nil unless input.scan_until(%r{</#{name}[ \t\r\n]*>}i)
            next
          end
          if active
            depth += 1 if !closing && name == active
            depth -= 1 if closing && name == active
            if depth.zero?
              blocks << [active, text]
              active = nil
              text = +''
            else
              text << ' '
            end
          elsif !closing && (name == 'h3' || (name == 'div' && alert_classes?(tag)))
            active = name
            depth = 1
          end
        end
        active ? nil : blocks
      end

      def alert_classes?(tag)
        value = tag[/\bclass[ \t]*=[ \t]*["']([^"']*)["']/i, 1]
        classes = value.to_s.split
        classes.include?('alert') && classes.include?('alert-danger')
      end
    end
  end
end
