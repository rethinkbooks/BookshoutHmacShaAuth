# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'BookshoutHmacShaAuth/version'
require 'hmac_shable'
require 'hmac_sha_generator'

Gem::Specification.new do |spec|
  spec.name          = "BookshoutHmacShaAuth"
  spec.version       = BookshoutHmacShaAuth::VERSION
  spec.authors       = ["Eric Roos"]
  spec.email         = ["eric@bookshout.com"]
  spec.summary       = "Gem containing a ActiveSupport concern for habling HmacSha auth"
  spec.description   = ""
  spec.homepage      = ""
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.7"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_dependency "activesupport"
end
