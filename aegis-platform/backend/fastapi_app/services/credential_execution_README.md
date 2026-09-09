# Credential execution integration

The execution plane accepts credential references only through `credential_refs`. Capability adapters must explicitly declare a credential mode before references are accepted.

Current production-proven binding:

- `web.security-headers` resolves one Vault reference inside the worker and provides it to curl through a temporary 0600 config file.

The invariant is tested by Credential Vault Reality and Native Capability Reality: no plaintext secret may appear in task args, scan config, API responses, stdout, stderr, Evidence metadata, execution result data, scan logs, or audit metadata.
