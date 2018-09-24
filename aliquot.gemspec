lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |s|
  s.name     = 'aliquot'
  s.version  = '0.0.1'
  s.author   = 'Clearhaus'
  s.email    = 'hello@clearhaus.com'
  s.summary  = 'To decrypt Google Pay tokens'

  s.files = Dir.glob('lib/**/*.rb')
end
