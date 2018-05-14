
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "schnorr/version"

Gem::Specification.new do |spec|
  spec.name          = "schnorr"
  spec.version       = Schnorr::VERSION
  spec.authors       = ["azuchi"]
  spec.email         = ["azuchi@haw.co.jp"]

  spec.summary       = %q{Schnorr signature for Ruby.}
  spec.description   = %q{Schnorr signature for Ruby.}
  spec.homepage      = "https://github.com/haw-itn/schnorr"
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.16"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
end
