# Aliquot #

[![CircleCI](https://circleci.com/gh/clearhaus/aliquot/tree/master.svg?style=svg)](https://circleci.com/gh/clearhaus/aliquot/tree/master)
[![Gem Version](https://badge.fury.io/rb/aliquot.svg)](https://badge.fury.io/rb/aliquot)

## Example usage ##

To run sample_token_poc.rb

```
ruby -I lib sample_token_poc.rb
```
The file ` sample_token_poc.rb` contains a GooglePay token for `gateway:epay` with gateway merchant id: `0123456789` created with [GooglePay token generator](https://developers.google.com/pay/api/processors/guides/test-and-validation/token-generator) and the calculated shared_secret - `googlepay[shared_key]` [mentioned here](https://docs.gateway.clearhaus.com/#authorizations). 

It uses the library to validate signatures and decrypts the token and dumps it to stdout. <br>
The token is valid for a week as I remember.

Minor changes in payment.rb - all related to preserving `\u003d` before various checks are calculated - as suggested here [GooglePay Developer Doc](https://developers.google.com/pay/api/processors/guides/implementation/verify-signatures#how-to-construct).<br>
The code still contains a lot of dumps for debugging/understanding purposes - including complete token and (test) carddata :-O


I have not spent time on updating the unittest's - new to Ruby and especially the RSpec testing framework!