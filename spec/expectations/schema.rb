require 'rspec/expectations'

RSpec::Matchers.define :satisfy_schema do |expected|
  match do |actual|
    @check = expected.call(actual)
    @check.success?
  end

  failure_message do
    <<~EOM
      expected that the given hash satisfy the schema, but:
        #{@check}
    EOM
  end
end

RSpec::Matchers.define :dissatisfy_schema do |expected, mismatch|
  match do |actual|
    check = expected.call(actual)
    @mismatches = mismatch
    @errors = actual.messages

    return false if check.success?

    return true unless mismatch

    key = mismatch.keys[0]
    filtered_messages = actual.messages.select { |message| message.path[0] == key }

    return false unless filtered_messages.length > 0

    value = mismatch[key][0]
    filtered_texts = (value.is_a? Array) ?
                       filtered_messages.select { |message| message.text == value[0] } :
                       filtered_messages.select { |message| message.text == value }

    return false unless filtered_texts.length == 1

    true
  end

  failure_message do
    <<~EOM
      expected that the given hash unsatisfy the schema this way:
        #{@mismatches}
      but got:
        #{@errors}
    EOM
  end
end
