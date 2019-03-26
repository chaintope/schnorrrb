require "bundler/setup"
require "schnorr"

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end

def fixture_file(relative_path)
  File.read(File.join(File.dirname(__FILE__), 'fixtures', relative_path))
end
