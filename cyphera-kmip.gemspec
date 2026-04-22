# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name          = "cyphera-kmip"
  spec.version       = "0.0.1.alpha1"
  spec.authors       = ["Leslie Gutschow"]
  spec.email         = ["leslie.gutschow@horizondigital.dev"]
  spec.summary       = "KMIP client for Ruby"
  spec.description   = "KMIP client for Ruby — connect to any KMIP-compliant key management server (Thales, IBM SKLM, Entrust, Fortanix, HashiCorp Vault)."
  spec.homepage      = "https://github.com/cyphera-labs/kmip-ruby"
  spec.license       = "Apache-2.0"

  spec.required_ruby_version = ">= 3.1"

  spec.metadata["homepage_uri"]    = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage

  spec.files = Dir["lib/**/*.rb"] + ["LICENSE", "README.md"]
  spec.require_paths = ["lib"]

  spec.add_development_dependency "minitest", "~> 5.0"
  spec.add_development_dependency "rake", "~> 13.0"
end
