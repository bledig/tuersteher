# Generated by jeweler
# DO NOT EDIT THIS FILE DIRECTLY
# Instead, edit Jeweler::Tasks in Rakefile, and run 'rake gemspec'
# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{tuersteher}
  s.version = "0.6.5"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Bernd Ledig"]
  s.date = %q{2011-09-08}
  s.description = %q{Security-Layer for Rails-Application acts like a firewall.}
  s.email = %q{bernd@ledig.info}
  s.extra_rdoc_files = [
    "README.rdoc"
  ]
  s.files = [
    "Manifest",
    "README.rdoc",
    "Rakefile",
    "VERSION",
    "init.rb",
    "lib/tuersteher.rb",
    "license.txt",
    "samples/access_rules.rb",
    "samples/application_controller.rb",
    "spec/acces_rules_storage_spec.rb",
    "spec/access_rules_spec.rb",
    "spec/model_access_rule_spec.rb",
    "spec/model_extensions_spec.rb",
    "spec/path_access_rule_spec.rb",
    "spec/spec.opts",
    "spec/spec_helper.rb",
    "tuersteher.gemspec"
  ]
  s.homepage = %q{http://github.com/bledig/tuersteher}
  s.require_paths = ["lib"]
  s.rubygems_version = %q{1.6.2}
  s.summary = %q{Security-Layer for Rails-Application}

  if s.respond_to? :specification_version then
    s.specification_version = 3
    #test
  end
end

