# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{tuersteher}
  s.version = "0.0.5"

  s.required_rubygems_version = Gem::Requirement.new(">= 1.2") if s.respond_to? :required_rubygems_version=
  s.authors = ["Bernd Ledig"]
  s.date = %q{2009-08-10}
  s.description = %q{Security-Layer for Rails-Application acts like a firewall.}
  s.email = %q{bernd@ledig.info}
  s.extra_rdoc_files = ["lib/tuersteher.rb"]
  s.files = ["lib/tuersteher.rb", "Rakefile", "init.rb", "Manifest", "tuersteher.gemspec"]
  s.homepage = %q{http://github.com/bledig/tuersteher}
  s.rdoc_options = ["--line-numbers", "--inline-source", "--title", "Tuersteher", "--main", "README.rdoc"]
  s.require_paths = ["lib"]
  s.rubyforge_project = %q{tuersteher}
  s.rubygems_version = %q{1.3.5}
  s.summary = %q{Security-Layer for Rails-Application acts like a firewall.}

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 3

    if Gem::Version.new(Gem::RubyGemsVersion) >= Gem::Version.new('1.2.0') then
    else
    end
  else
  end
end
