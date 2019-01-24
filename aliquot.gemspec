lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |s|
  s.name     = 'aliquot'
  s.version  = '0.16.0'
  s.author   = 'Clearhaus'
  s.email    = 'hello@clearhaus.com'
  s.summary  = 'Validates Google Pay tokens'
  s.license  = 'MIT'
  s.homepage = 'https://github.com/clearhaus/aliquot'

  s.files = Dir.glob('lib/**/*.rb')

  s.add_runtime_dependency 'dry-validation', '~> 0'
  s.add_runtime_dependency 'excon',          '~> 0'
  s.add_runtime_dependency 'hkdf',           '~> 0'

  s.add_development_dependency 'aliquot-pay', '~> 0.13.0'
  s.add_development_dependency 'rspec',       '~> 3'
end
