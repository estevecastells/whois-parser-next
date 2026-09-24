# frozen_string_literal: true

require_relative "lib/whois/parser/version"

Gem::Specification.new do |spec|
  spec.name = "whois-parser-next"
  spec.version = Whois::Parser::VERSION
  spec.authors = ["Simone Carletti", "Esteve Castells"]
  spec.homepage = "https://domscan.net/whois-api"
  spec.summary = "A community-maintained Ruby WHOIS parser"
  spec.description = "A maintained successor to weppos/whois-parser that parses WHOIS responses into Ruby objects."
  spec.license = "MIT"

  spec.required_ruby_version = ">= 3.2"

  spec.require_paths = %w[lib]
  documentation_files = %w[
    CHANGELOG.md
    CODE_OF_CONDUCT.md
    CONTRIBUTING.md
    GOVERNANCE.md
    LICENSE.txt
    MAINTAINERS.md
    README.md
    RELEASING.md
    ROADMAP.md
    SECURITY.md
  ]
  spec.files = `git ls-files -z -- lib #{documentation_files.join(' ')}`
               .split("\x0")
               .select { |file| File.file?(file) }
  spec.extra_rdoc_files = documentation_files

  spec.metadata = {
    "bug_tracker_uri" => "https://github.com/estevecastells/whois-parser-next/issues",
    "changelog_uri" => "https://github.com/estevecastells/whois-parser-next/blob/main/CHANGELOG.md",
    "homepage_uri" => "https://domscan.net/whois-api",
    "rubygems_mfa_required" => "true",
    "source_code_uri" => "https://github.com/estevecastells/whois-parser-next",
  }

  spec.add_dependency "activesupport", ">= 7.1", "< 9"
  spec.add_dependency "whois", ">= 6", "< 7"

  spec.add_development_dependency "rake", ">= 13.2", "< 14"
  spec.add_development_dependency "rspec", ">= 3.13", "< 4"
  spec.add_development_dependency "csv", ">= 3.2", "< 4"
  spec.add_development_dependency "yard", ">= 0.9", "< 1"
end
