# bindings/ts

TypeScript source for `@godesk/encryptoglyph`. The runtime is `js/envelope.js`, a byte-for-byte copy of `sdk/js/envelope.js`. Installing this directory does not run `wasm-pack` or `tsc`.

Node.js 24 or newer:

```bash
npm install ./bindings/ts
node --experimental-strip-types -e "import { Keyring } from '@godesk/encryptoglyph'"
```

From git:

```bash
npm install github:GoDeskio/Encryptoglyph#<ref>:bindings/ts
```

The repository-root package and `sdk/js` publish the same name and the same envelope. Use whichever path your installer accepts. Konektor (Node) should depend on the root package or `sdk/js`.
