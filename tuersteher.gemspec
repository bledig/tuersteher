# encoding: utf-8
$:.push File.expand_path("../lib", __FILE__)

Gem::Specification.new do |s|
  s.name        = 'tuersteher'
  s.version     = '0.7.2'
  s.authors     = ["Bernd Ledig"]
  s.email       = ["bernd@ledig.info"]
  s.homepage    = "http://github.com/bledig/tuersteher"
  s.summary     = "summary of the gem"
  s.description = <<-EOT
    Security-Layer for Rails-Application acts like a firewall.
  EOT

  s.rubyforge_project = "tuersteher"

  s.extra_rdoc_files = ["README.rdoc"]
  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  #s.add_runtime_dependency "i18n"

  s.add_development_dependency "rake"
  s.add_development_dependency "rspec", '>2.7', '<3.0'

end

