# Aliquot

A Ruby gem that will help you handle Google Pay tokens.

## Usage

For usage examples it's best to look at unit tests. As an example from `dummy_spec.rb`.

```ruby
# token_string:  Google Pay token (JSON string)
# shared_secret: Base64 encoded shared secret (EC Public key)
# merchant_id:   Google Pay merchant ID ("merchant:<SOMETHING>")
a = Aliquot::Payment.new(token_string, shared_secret, merchant_id)
a.process
```

## Unit tests

To be sure that unit tests run properly, you can run them in a docker container.

```bash
docker run -ti --rm -v $(pwd):/opt/aliquot ruby:2.3 bash
cd /opt/aliquot
bundle install
bundle exec rspec
```
