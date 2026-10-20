//go:build ignore

// Renders an AppArmor profile template the way the container runtimes
// render theirs: reads the Go source file that defines the template as a
// string constant, and executes it with text/template and the data given
// as JSON. Used by tests/apparmor_fetch_corpus.sh.
//
// Usage: go run tests/apparmor_render.go FILE CONST JSON
package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"strconv"
	"text/template"
)

func main() {
	if len(os.Args) != 4 {
		log.Fatal("usage: apparmor_render.go FILE CONST JSON")
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, os.Args[1], nil, 0)
	if err != nil {
		log.Fatal(err)
	}
	var text string
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, name := range spec.Names {
			if name.Name != os.Args[2] || i >= len(spec.Values) {
				continue
			}
			lit, ok := spec.Values[i].(*ast.BasicLit)
			if !ok {
				log.Fatalf("%s is not a string literal", os.Args[2])
			}
			text, err = strconv.Unquote(lit.Value)
			if err != nil {
				log.Fatal(err)
			}
			found = true
		}
		return true
	})
	if !found {
		log.Fatalf("no constant %s in %s", os.Args[2], os.Args[1])
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(os.Args[3]), &data); err != nil {
		log.Fatal(err)
	}
	// JSON numbers decode as float64; the templates compare with int.
	for k, v := range data {
		if f, ok := v.(float64); ok && f == float64(int(f)) {
			data[k] = int(f)
		}
	}
	t := template.Must(template.New("profile").Option("missingkey=error").Parse(text))
	if err := t.Execute(os.Stdout, data); err != nil {
		log.Fatal(err)
	}
}
