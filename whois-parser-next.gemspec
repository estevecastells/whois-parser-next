# frozen_string_literal: true

require_relative "lib/whois/parser/version"

Gem::Specification.new do |spec|
  spec.name = "whois-parser-next"
  spec.version = Whois::Parser::VERSION
  spec.authors = ["Simone Carletti", "Esteve Castells"]
  spec.homepage = "https://github.com/estevecastells/whois-parser-next"
  spec.summary = "A community-maintained Ruby WHOIS parser"
  spec.description = "A maintained successor to weppos/whois-parser that parses WHOIS responses into Ruby objects."
  spec.license = "MIT"

  spec.required_ruby_version = ">= 3.2"

  spec.require_paths = %w[lib]
  spec.files = `git ls-files -z`.split("\x0").select { |file| File.file?(file) }
  spec.extra_rdoc_files = %w[LICENSE.txt .yardopts]

  spec.metadata = {
    "bug_tracker_uri" => "https://github.com/estevecastells/whois-parser-next/issues",
    "changelog_uri" => "https://github.com/estevecastells/whois-parser-next/blob/main/CHANGELOG.md",
    "source_code_uri" => "https://github.com/estevecastells/whois-parser-next",
  }

  spec.add_dependency "activesupport", ">= 7.1", "< 9"
  spec.add_dependency "ostruct", ">= 0.6", "< 1"
  spec.add_dependency "whois", ">= 6", "< 7"

  spec.add_development_dependency "rake"
  spec.add_development_dependency "rspec"
  spec.add_development_dependency "yard"
end
