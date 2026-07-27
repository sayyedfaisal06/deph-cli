# @sayyedfaisal06/deph-cli

The `deph` command.

Audits the dependencies of every project in a repo — npm, Python, cargo, Go,
Ruby, PHP — for known vulnerabilities, outdated versions, and licenses you
don't allow, against a policy you commit to the repo in a `.deph` file.

```console
npx @sayyedfaisal06/deph-cli init      # writes repo.deph with a starting policy
npx @sayyedfaisal06/deph-cli scan      # finds manifests, looks up versions and advisories
npx @sayyedfaisal06/deph-cli check     # applies the policy; exit 1 if anything fails
npx @sayyedfaisal06/deph-cli studio    # dashboard on localhost
```

Or install it once and the command is just `deph`:

```console
npm install -g @sayyedfaisal06/deph-cli
deph check
```

Full documentation: https://github.com/sayyedfaisal06/deph

## What this package is

deph is written in Python with no dependencies at all — stdlib only. This
package vendors that source and runs it with whatever `python3` is already on
the machine. There is nothing to compile and nothing to `pip install`.

It exists so a Node pipeline doesn't need a Python setup step to audit its own
`package-lock.json`. It is the same tool as `pipx install deph-cli`, at the same
version.

## Requirements

Python 3.9 or newer on `PATH`. macOS and every mainstream Linux CI image
already have one; on Windows you may need to install it from python.org with
"Add to PATH" ticked.

Set `DEPH_PYTHON` to an absolute path to pin a specific interpreter. It is
honoured exclusively — if it isn't usable, deph fails rather than quietly
falling back to a different one.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | No failing findings. |
| 1 | At least one `fail` finding. |
| 2 | Couldn't get far enough to judge: no `.deph` file, several of them, a parse error, or no usable Python. |
| 130 | Interrupted. |

The wrapper passes the exit code through untouched, so `npx @sayyedfaisal06/deph-cli check` is safe
to use as a CI gate.

## License

MIT.
