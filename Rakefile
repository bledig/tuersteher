# Rakefile
require 'rubygems'
require 'rake'

=begin

require 'echoe'

Echoe.new('tuersteher', '0.0.5') do |p|
  p.description    = "Security-Layer for Rails-Application acts like a firewall."
  p.url            = "http://github.com/bledig/tuersteher"
  p.author         = "Bernd Ledig"
  p.email          = "bernd@ledig.info"
  p.ignore_pattern = ["tmp/*", "script/*"]
  p.development_dependencies = []
end

=end

begin
  require 'jeweler'
  Jeweler::Tasks.new do |gemspec|
    gemspec.name = "tuersteher"
    gemspec.summary = "Security-Layer for Rails-Application"
    gemspec.description = "Security-Layer for Rails-Application acts like a firewall."
    gemspec.email = "bernd@ledig.info"
    gemspec.homepage = "http://github.com/bledig/tuerstehe"
    gemspec.authors = ["Bernd Ledig"]
  end
rescue LoadError
  puts "Jeweler not available. Install it with: sudo gem install technicalpickles-jeweler -s http://gems.github.com"
end

Dir["#{File.dirname(__FILE__)}/tasks/*.rake"].sort.each { |ext| load ext }

