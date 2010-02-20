# Rakefile
require 'rubygems'
require 'rake'

begin
  require 'jeweler'
  Jeweler::Tasks.new do |gemspec|
    gemspec.name = "tuersteher"
    gemspec.summary = "Security-Layer for Rails-Application"
    gemspec.description = "Security-Layer for Rails-Application acts like a firewall."
    gemspec.email = "bernd@ledig.info"
    gemspec.homepage = "http://github.com/bledig/tuersteher"
    gemspec.authors = ["Bernd Ledig"]
  end
rescue LoadError
  puts "Jeweler not available. Install it with: sudo gem install jeweler -s http://gems.github.com"
end

Dir["#{File.dirname(__FILE__)}/tasks/*.rake"].sort.each { |ext| load ext }

