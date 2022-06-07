package kubernetes.admission

deny[msg] {
	provided := {label | input.request.object.metadata.labels[label]}
	required := {label | label := input.request.object.labels[_].key}
	missing := required - provided
	count(missing) > 0

	msg := "Missing labels"
}

deny[msg] {
	value := input.request.object.metadata.labels[key]
	expected := data.labels[_]
	expected.key == key

	# do not match if allowedRegex is not defined, or is an empty string
	expected.allowedRegex != ""
	not re_match(expected.allowedRegex, value)

	msg := "Missing labels"
}
