// Read Go's ELF function table directly. This is independent of vulnerability matching.
package main

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"debug/gosym"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func normalized(name string) string {
	return strings.ReplaceAll(strings.ReplaceAll(name, "(*", ""), ")", "")
}

func inspect(path string, queries []string) (map[string]any, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 256<<20 {
		return nil, fmt.Errorf("input is not a bounded regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 256<<20 {
		return nil, fmt.Errorf("input read failed or exceeded limit")
	}
	file, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	pcln, text := file.Section(".gopclntab"), file.Section(".text")
	if pcln == nil || text == nil || pcln.Size > 64<<20 {
		return nil, fmt.Errorf("supported Go function table unavailable")
	}
	tableBytes, err := pcln.Data()
	if err != nil {
		return nil, err
	}
	table, err := gosym.NewTable(nil, gosym.NewLineTable(tableBytes, text.Addr))
	if err != nil {
		return nil, err
	}
	if len(table.Funcs) == 0 {
		return nil, fmt.Errorf("empty Go function table")
	}
	matches := []map[string]any{}
	for _, query := range queries {
		found := []map[string]any{}
		for _, fn := range table.Funcs {
			if normalized(fn.Name) != normalized(query) {
				continue
			}
			for _, segment := range file.Progs {
				if segment.Type == elf.PT_LOAD && segment.Flags&elf.PF_X != 0 && fn.Entry >= segment.Vaddr && fn.End > fn.Entry && fn.End <= segment.Vaddr+segment.Memsz {
					found = append(found, map[string]any{"name": fn.Name, "entry": fn.Entry, "end": fn.End})
					break
				}
			}
		}
		state := "not_observed"
		if len(found) > 0 {
			state = "present_in_function_table"
		}
		matches = append(matches, map[string]any{"query": query, "status": state, "matches": found})
	}
	sum := sha256.Sum256(data)
	return map[string]any{"status": "observed", "sha256": hex.EncodeToString(sum[:]), "method": "elf_go_pclntab_v1", "format": "ELF", "architecture": file.Machine.String(), "function_count": len(table.Funcs), "symbols": matches,
		"limitations": []string{"Positive matches identify compiled functions in executable segments, not runtime reachability.", "Not observed does not establish absence: inlining, linker transformations, assembly and unsupported formats can hide code."}}, nil
}

func main() {
	defer func() {
		if recover() != nil {
			fmt.Println(`{"status":"unavailable","reason":"invalid Go function table"}`)
			os.Exit(1)
		}
	}()
	if len(os.Args) < 3 || len(os.Args) > 22 {
		fmt.Println(`{"status":"unavailable","reason":"requires path and 1-20 symbol names"}`)
		os.Exit(1)
	}
	for _, query := range os.Args[2:] {
		if len(query) > 512 {
			os.Exit(1)
		}
	}
	result, err := inspect(os.Args[1], os.Args[2:])
	if err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "unavailable", "reason": err.Error()})
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
}
