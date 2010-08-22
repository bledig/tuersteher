# Generated by jeweler
# DO NOT EDIT THIS FILE DIRECTLY
# Instead, edit Jeweler::Tasks in Rakefile, and run the gemspec command
# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{tuersteher}
  s.version = "0.1.4"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Bernd Ledig"]
  s.date = %q{2010-08-22}
  s.description = %q{Security-Layer for Rails-Application acts like a firewall.}
  s.email = %q{bernd@ledig.info}
  s.extra_rdoc_files = [
    "README.rdoc"
  ]
  s.files = [
    ".gitignore",
     "Manifest",
     "README.rdoc",
     "Rakefile",
     "VERSION",
     "init.rb",
     "lib/tuersteher.rb",
     "license.txt",
     "samples/access_rules.rb",
     "samples/application_controller.rb",
     "tuersteher.gemspec"
  ]
  s.homepage = %q{http://github.com/bledig/tuersteher}
  s.rdoc_options = ["--charset=UTF-8"]
  s.require_paths = ["lib"]
  s.rubygems_version = %q{1.3.6}
  s.summary = %q{Security-Layer for Rails-Application}

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 3

    if Gem::Version.new(Gem::RubyGemsVersion) >= Gem::Version.new('1.2.0') then
    else
    end
  else
  end
end

