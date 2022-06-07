.PHONY: kwctl
kwctl:
	@clear
	@go run . --kwctl

.PHONY: policy-server
policy-server:
	@clear
	@go run . --policy-server

.PHONY: gatekeeper
gatekeeper:
	@clear
	@go run . --gatekeeper

.PHONY: opa
opa:
	@clear
	@go run . --opa
