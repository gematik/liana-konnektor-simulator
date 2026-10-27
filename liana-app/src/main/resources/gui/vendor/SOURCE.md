# preact-htm.js

Preact mit Hooks und htm in einer ES-Modul-Datei, so wie sie im npm-Paket `htm` liegt (decision-018, LIANA-148).

| | |
|---|---|
| Paket | `htm` 3.1.1 (https://www.npmjs.com/package/htm, https://github.com/developit/htm) |
| Datei im Paket | `preact/standalone.module.js`, unverändert |
| Tarball | https://registry.npmjs.org/htm/-/htm-3.1.1.tgz |
| Integrität (npm, sha512) | `983Vyg8NwUE7JkZ6NmOqpCZ+sh1bKv2iYTlUkzlWmA5JD2acKoxd4KVxbMmxX/85mtfdnDmTFoNKcg5DGAvxNQ==` |
| SHA-256 der Datei | `72284e8e9079c87817145df1110f74e8a2aa040b2fc384922e18dfcb46fc1fd7` |
| Enthält | Preact 10 (`h`, `render`, `Component`, `createContext`), Preact Hooks (`useState`, `useEffect`, `useRef`, `useMemo`, `useCallback`, …), `html` (htm an `h` gebunden) |
| Lizenzen | htm: Apache-2.0 (`LICENSE-htm.txt`, aus dem Tarball); Preact: MIT (`LICENSE-preact.txt`, aus `preact` 10.2.0, der Version, gegen die htm 3.1.1 gebaut ist) |
| Geholt | 2026-10-16 |

Update von Hand: Tarball laden, Integrität gegen `npm view htm dist.integrity` prüfen, `package/preact/standalone.module.js` hierher kopieren, Tabelle nachziehen. Kein Node im Build.
