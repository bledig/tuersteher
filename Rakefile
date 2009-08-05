# Rakefile
require 'rubygems'
require 'rake'
require 'echoe'

Echoe.new('tuersteher', '0.1.0') do |p|
  p.description    = "Security-Layer for Rails-Application acts like a firewall."
  p.url            = "http://github.com/bledig/tuersteher"
  p.author         = "Bernd Ledig"
  p.email          = "bernd@ledig.info"
  p.ignore_pattern = ["tmp/*", "script/*"]
  p.development_dependencies = []
end

Dir["#{File.dirname(__FILE__)}/tasks/*.rake"].sort.each { |ext| load ext }

