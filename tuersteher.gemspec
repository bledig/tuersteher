# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |gem|
  gem.name          = "tuersteher"
  gem.version       = "0.7.0"
  gem.authors       = ["Bernd Ledig"]
  gem.email         = %q{bernd@ledig.info}
  gem.description   = "Rails-Access-Control-Framework"
  gem.description   = %q{Security-Layer for Rails-Application acts like a firewall.}
  gem.homepage      = %q{http://github.com/bledig/tuersteher}

  gem.files         = `git ls-files`.split($/)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]

  gem.add_development_dependency "rake"
  gem.add_development_dependency "rspec", '>2.7', '<3.0'

  if gem.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    gem.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
    else
    end
  end
end

