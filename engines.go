// Package raijinsecrets holds the engine versions this tool is tested with (engines.json), embedded so
// the binary knows them.
package raijinsecrets

import _ "embed"

// EnginesJSON is engines.json: for each engine, the version the benchmark fixtures were produced with
// and where to install it from.
//
//go:embed engines.json
var EnginesJSON []byte
