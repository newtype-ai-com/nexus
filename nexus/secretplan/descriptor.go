package secretplan

// RoleDescriptor is the public, static plan/3 descriptor of one role: exactly
// the role object of the approved plan (Validate checked every key), rebuilt
// from the parsed Role so a consumer can compare it field by field with its
// own manifest. Nexus signs it into run receipts (newtype.run-receipt/2): the
// stored plan is the single source of what the executor runs.
//
//   - every role: role, source, resource, fd, max_bytes, payload_schema, delivery
//   - nexus: name, generation (the pinned generation, never "latest")
//   - keychain-helper: ref {keychain, service, account} (the exact item),
//     helper {path, sha256, cdhash}, argv, schema, custody_evidence_sha256,
//     helper_output_schema, expected_environment (no generation: a Keychain
//     item has none, and none is invented)
//
// Only plan/3 roles have a descriptor; it carries no secret value, digest or
// length of one.
func RoleDescriptor(r Role) map[string]any {
	d := map[string]any{"role": r.Role, "source": r.Source, "resource": r.Resource, "fd": r.FD,
		"max_bytes": r.MaxBytes, "payload_schema": r.PayloadSchema, "delivery": r.Delivery}
	switch r.Source {
	case "nexus":
		d["name"], d["generation"] = r.Name, r.Generation
	case "keychain-helper":
		d["ref"] = map[string]any{"keychain": r.Keychain, "service": r.Service, "account": r.Account}
		d["helper"] = map[string]any{"path": r.HelperPath, "sha256": r.HelperSHA256, "cdhash": r.HelperCDHash}
		argv := make([]any, 0, len(r.HelperArgv))
		for _, a := range r.HelperArgv {
			argv = append(argv, a)
		}
		d["argv"] = argv
		d["schema"] = r.SchemaVersion
		d["custody_evidence_sha256"] = r.CustodyEvidence
		d["helper_output_schema"], d["expected_environment"] = r.HelperOutputSchema, r.ExpectedEnvironment
	}
	return d
}
