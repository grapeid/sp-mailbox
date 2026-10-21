# Contributing

Contributions are welcome — bug reports, fixes and improvements alike.

## Sign off every commit

This project uses the [Developer Certificate of Origin](https://developercertificate.org/)
(DCO). Every commit must carry a `Signed-off-by` line certifying that you wrote
the change, or otherwise have the right to submit it under this project's
licence:

```
Signed-off-by: Your Name <you@example.org>
```

`git commit -s` adds it for you. The name and email must match the commit's
author. A pull request containing an unsigned commit cannot be merged; fix it
with `git commit --amend -s` or `git rebase --signoff`.

## Before opening a pull request

```sh
go build ./...
go vet ./...
go test ./...
```

All three must pass.

## Licence

By contributing, you agree that your contribution is licensed under the
Apache License, Version 2.0 (see `LICENSE`).

## Security issues

Do not open a public issue for a vulnerability. See `SECURITY.md`.
