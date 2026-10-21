package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestStrippedELFPositiveAndNoFalseNegative(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "main.go")
	err := os.WriteFile(source, []byte("package main\nimport \"fmt\"\n//go:noinline\nfunc retained(s string) { fmt.Println(s) }\nfunc main() { retained(\"fixture\") }\n"), 0600)
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "binary")
	command := exec.Command("go", "build", "-ldflags=-s -w", "-o", binary, source)
	command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOTOOLCHAIN=local")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build: %s %v", output, err)
	}
	result, err := inspect(binary, []string{"main.retained", "main.nonexistent"})
	if err != nil {
		t.Fatal(err)
	}
	symbols := result["symbols"].([]map[string]any)
	if symbols[0]["status"] != "present_in_function_table" {
		t.Fatal(symbols)
	}
	if symbols[1]["status"] != "not_observed" {
		t.Fatal(symbols)
	}
}
