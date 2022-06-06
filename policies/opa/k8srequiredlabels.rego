package kubernetes.admission

get_message(parameters, _default) = msg {
	not parameters.message
	msg := _default
}

get_message(parameters, _default) = msg {
	msg := parameters.message
}

deny[msg] {
	provided := {label | input.review.object.metadata.labels[label]}
	required := {label | label := input.parameters.labels[_].key}
	missing := required - provided
	count(missing) > 0
	def_msg := sprintf("you must provide labels: %v", [missing])
	msg := get_message(input.parameters, def_msg)
}

deny[msg] {
	value := input.review.object.metadata.labels[key]
	expected := input.parameters.labels[_]
	expected.key == key

	# do not match if allowedRegex is not defined, or is an empty string
	expected.allowedRegex != ""
	not re_match(expected.allowedRegex, value)
	def_msg := sprintf("Label <%v: %v> does not satisfy allowed regex: %v", [key, value, expected.allowedRegex])
	msg := get_message(input.parameters, def_msg)
}
