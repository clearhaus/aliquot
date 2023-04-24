lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |s|
  s.name     = 'aliquot'
  s.version  = '2.1.4'
  s.author   = 'Clearhaus'
  s.email    = 'hello@clearhaus.com'
  s.summary  = 'Validates Google Pay tokens'
  s.license  = 'MIT'
  s.homepage = 'https://github.com/clearhaus/aliquot'

  s.files = Dir.glob('lib/**/*.rb')

  s.required_ruby_version = '>= 2.7'

  s.add_runtime_dependency 'dry-validation', '~> 1.8'
  s.add_runtime_dependency 'excon',          '~> 0.71.0'
  s.add_runtime_dependency 'hkdf',           '~> 0.3'

  s.add_development_dependency 'aliquot-pay', '~> 2.1.2'
  s.add_development_dependency 'rspec',       '~> 3'
  s.add_development_dependency 'pry',         '~> 0.14.1'
end
