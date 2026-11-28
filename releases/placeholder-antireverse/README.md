# antireverse

This name is reserved by the [Airverse](https://github.com/imransetiadi/antireverse) project. **This package contains no code**: no command, no library, no install script.

It exists so that nobody else can publish under this name. The Airverse command is called `antireverse`, and it ships in a different package:

```bash
npm install --save-dev @antireverse/harden
npx --no-install antireverse --help
```

`--no-install` makes npx run only the copy installed in your project. Without it, `npx antireverse` asks the registry for a package with this unscoped name, which is why the name is held here.

The packages of the project are `@antireverse/shield-node`, `@antireverse/guard` and `@antireverse/harden`.
