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

To be sure that unit tests run properly, you can run them in a Docker container.

```bash
docker run -ti --rm -v $(pwd):/opt/aliquot ruby:2.7.4 bash
cd /opt/aliquot
bundle install
bundle exec rspec
exit
```

## Publishing new Gem

Beware of cyclic dependency with `aliquot-pay`. Update the new versions 
for these gems in parallel.

1. Update [./aliquot.gemspec](./aliquot.gemspec)
    ```gemspec
    Gem::Specification.new do |s|
      s.name     = 'aliquot'
      s.version  = '${NEW_ALIQUOT_VERSION}'
      ...
      s.add_development_dependency 'aliquot-pay', '~> ${NEW_ALIQUOT-PAY_VERSION}'
      ...
    end
    ```

2. Run the following
    ```bash
    gem build
    gem push aliquot-${NEW_ALIQUOT_VERSION}.gem
    ```

3. Then do the same for `aliquot-pay` if not already done.
