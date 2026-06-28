# Testing

Run local tests with:

```sh
go test ./...
```

Live Forgejo/Codeberg tests are intentionally not part of the default scaffold.
When added, they should be skipped unless explicit environment variables are set
and must never require real tokens in normal CI or local test runs.
