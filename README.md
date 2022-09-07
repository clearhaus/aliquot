# Aliquot #

[![CircleCI](https://circleci.com/gh/clearhaus/aliquot/tree/master.svg?style=svg)](https://circleci.com/gh/clearhaus/aliquot/tree/master)
[![Gem Version](https://badge.fury.io/rb/aliquot.svg)](https://badge.fury.io/rb/aliquot)

## Example usage ##

For usage examples it's best to look at unit tests. As an example from `dummy_spec.rb`.

```ruby
# token_string::  Google Pay token (JSON string)
# shared_secret:: Base64 encoded shared secret (EC Public key)
# recipient_id::  Google Pay recipient ID ("<PREFIX e.g. merchant>:<SOMETHING>")
a = Aliquot::Payment.new(token_string, shared_secret, recipient_id)
a.process
```

## Unit tests ##

To be sure that unit tests run properly, you can run them in a docker container.

```bash
docker run -ti --rm -v $(pwd):/opt/aliquot ruby:2.7.4 bash
cd /opt/aliquot
bundle install
bundle exec rspec
```
