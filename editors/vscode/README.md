# deph for VS Code

Two things, for [deph](https://github.com/sayyedfaisal06/deph) `.deph` files:

* A TextMate grammar, so policy rules, waivers, project and dep blocks,
  severities, advisory ids and the generated marker are all highlighted.
* A **Deph: Open Studio** command that runs `deph studio` in a terminal. Needs
  deph on your PATH (`pip install deph-cli`).

Not published to the marketplace. Build and install it yourself:

```console
cd editors/vscode
npx @vscode/vsce package        # writes deph-vscode-<version>.vsix
```

Then "Extensions: Install from VSIX…".
