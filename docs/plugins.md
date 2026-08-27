# Verified plugin distribution

AegisScan supports opt-in plugin synchronization through the core `PluginRegistry` and `PluginManager` APIs.

Each registry entry must include:

```json
{
  "name": "example-plugin",
  "version": "1.0.0",
  "source_url": "https://updates.example.test/example-plugin.zip",
  "sha256": "64-lowercase-hex-characters",
  "min_tool_versions": {"nmap": "7.8"},
  "trust_level": 0.8,
  "enabled": true
}
```

`sync_verified()` downloads only enabled entries whose version differs from the installed map. It requires HTTPS, enforces a 25 MiB limit, validates SHA-256 before installation, rejects path traversal and symbolic links, and stores each artifact under a versioned directory. Downloaded files are never imported or executed by the sync operation; activation remains a separate, reviewed step.

The registry is empty by default. This is deliberate: operators must review and pin every source and digest before enabling distribution in their environment.
