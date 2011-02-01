require 'rspec'
require 'logger'
require File.expand_path(File.dirname(__FILE__) + "/../lib/tuersteher")

# Logger auf stdout stellen
Tuersteher::TLogger.logger = Logger.new(STDOUT)
Tuersteher::TLogger.logger.level = Logger::ERROR
