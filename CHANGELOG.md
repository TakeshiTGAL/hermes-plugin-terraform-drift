# Changelog

## 0.1.1

- A relative `directory` was joined to the process working directory. On the gateway that directory is the gateway's own, not the session's. Hermes v0.23.1 adds `ctx.session_cwd`. When that method exists and returns an absolute path with no `..`, a relative directory is joined to it. Otherwise the process working directory is used, as on Hermes >=0.21.4 before v0.23.1. An absolute directory is unchanged. Checked with this repository's tests, and by loading the plugin on Hermes v0.22.2 and v0.23.1.
