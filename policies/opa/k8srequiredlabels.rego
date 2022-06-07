package kubernetes.admission

get_message(parameters, _default) = msg {
	not parameters.message
	msg := _default
}

get_message(parameters, _default) = msg {
	msg := parameters.message
}

deny[msg] {
	provided := {label | input.request.object.metadata.labels[label]}
	required := {label | label := data.labels[_].key}
	missing := required - provided
	count(missing) > 0
	msg := sprintf("you must provide labels: %v", [missing])
}

deny[msg] {
	value := input.request.object.metadata.labels[key]
	expected := data.labels[_]
	expected.key == key

	# do not match if allowedRegex is not defined, or is an empty string
	expected.allowedRegex != ""
	not re_match(expected.allowedRegex, value)
	msg := sprintf("Label <%v: %v> does not satisfy allowed regex: %v", [key, value, expected.allowedRegex])
}
