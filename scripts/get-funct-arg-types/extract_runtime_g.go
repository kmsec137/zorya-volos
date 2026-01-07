package main

import (
	"debug/dwarf"
	"encoding/json"
	"fmt"
	"os"
)

// RuntimeGOffsets holds the runtime.g struct field offsets
type RuntimeGOffsets struct {
	Goid         uint64            `json:"goid"`          // Goroutine ID offset
	Stack        *uint64           `json:"stack,omitempty"`        // Stack bounds
	Stackguard0  *uint64           `json:"stackguard0,omitempty"`  // Stack guard
	M            *uint64           `json:"m,omitempty"`            // Pointer to OS thread
	Atomicstatus *uint64           `json:"atomicstatus,omitempty"` // Atomic status
	AllFields    map[string]uint64 `json:"all_fields"`    // All discovered fields
}

// RuntimeInfo is the complete output structure
type RuntimeInfo struct {
	GoVersion      string          `json:"go_version"`
	BinaryPath     string          `json:"binary_path"`
	CriticalOffsets RuntimeGOffsets `json:"runtime_g_offsets"`
}

// ExtractRuntimeGOffsets searches for the runtime.g struct and extracts field offsets
func ExtractRuntimeGOffsets(dwarfData *dwarf.Data, binaryPath string) (*RuntimeInfo, error) {
	reader := dwarfData.Reader()
	
	// Search for runtime.g struct
	for {
		entry, err := reader.Next()
		if err != nil {
			return nil, fmt.Errorf("error reading DWARF: %v", err)
		}
		if entry == nil {
			break
		}
		
		// Look for struct types
		if entry.Tag != dwarf.TagStructType {
			continue
		}
		
		// Check if this is runtime.g
		var structName string
		for _, field := range entry.Field {
			if field.Attr == dwarf.AttrName {
				structName = field.Val.(string)
				break
			}
		}
		
		// Match "runtime.g" or just "g" (we'll verify it's the right struct)
		if structName != "runtime.g" && structName != "g" {
			continue
		}
		
		// Extract field offsets
		fieldOffsets := make(map[string]uint64)
		hasGoid := false
		hasStack := false
		
		// Iterate through struct members
		for {
			child, err := reader.Next()
			if err != nil {
				break
			}
			if child == nil || child.Tag == 0 {
				break
			}
			
			// Stop when we exit the struct
			if child.Tag != dwarf.TagMember {
				break
			}
			
			var fieldName string
			var fieldOffset uint64
			
			for _, attr := range child.Field {
				if attr.Attr == dwarf.AttrName {
					fieldName = attr.Val.(string)
				}
				if attr.Attr == dwarf.AttrDataMemberLoc {
					switch v := attr.Val.(type) {
					case int64:
						fieldOffset = uint64(v)
					case uint64:
						fieldOffset = v
					case []byte:
						// Some DWARF versions encode offsets as expressions
						if len(v) > 0 && v[0] == 0x23 { // DW_OP_plus_uconst
							offset, _ := readULEB128(v[1:])
							fieldOffset = offset
						}
					}
				}
			}
			
			if fieldName != "" {
				fieldOffsets[fieldName] = fieldOffset
				
				// Track critical fields for validation
				if fieldName == "goid" {
					hasGoid = true
				}
				if fieldName == "stack" {
					hasStack = true
				}
			}
		}
		
		// Validate this is the correct runtime.g struct
		// The real runtime.g must have both goid and stack fields
		if structName == "g" && (!hasGoid || !hasStack) {
			continue
		}
		
		if !hasGoid {
			return nil, fmt.Errorf("found %s struct but missing 'goid' field", structName)
		}
		
		// Build the result
		goidOffset := fieldOffsets["goid"]
		
		result := &RuntimeInfo{
			GoVersion:  extractGoVersionFromBinary(binaryPath),
			BinaryPath: binaryPath,
			CriticalOffsets: RuntimeGOffsets{
				Goid:      goidOffset,
				AllFields: fieldOffsets,
			},
		}
		
		// Add optional fields if present
		if stack, ok := fieldOffsets["stack"]; ok {
			result.CriticalOffsets.Stack = &stack
		}
		if sg0, ok := fieldOffsets["stackguard0"]; ok {
			result.CriticalOffsets.Stackguard0 = &sg0
		}
		if m, ok := fieldOffsets["m"]; ok {
			result.CriticalOffsets.M = &m
		}
		if status, ok := fieldOffsets["atomicstatus"]; ok {
			result.CriticalOffsets.Atomicstatus = &status
		}
		
		// Silent - no output needed
		
		return result, nil
	}
	
	return nil, fmt.Errorf("runtime.g struct not found in DWARF info")
}

// extractGoVersionFromBinary searches for the Go version string in the binary
func extractGoVersionFromBinary(binaryPath string) string {
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		return "unknown"
	}
	
	// Search for "go1." pattern
	pattern := []byte("go1.")
	for i := 0; i < len(data)-len(pattern); i++ {
		if string(data[i:i+len(pattern)]) == string(pattern) {
			// Extract version string (up to 20 chars or until whitespace/null)
			version := []byte{}
			for j := i; j < len(data) && j < i+20; j++ {
				b := data[j]
				if b == 0 || b == ' ' || b == '\t' || b == '\n' || b == '\r' {
					break
				}
				version = append(version, b)
			}
			
			versionStr := string(version)
			if len(versionStr) > 4 { // More than just "go1."
				// Silent - version detected
				return versionStr
			}
		}
	}
	
	return "unknown"
}

// SaveRuntimeGOffsets saves the runtime.g offsets to a JSON file
func SaveRuntimeGOffsets(info *RuntimeInfo, outputPath string) error {
	jsonData, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}
	
	err = os.WriteFile(outputPath, jsonData, 0644)
	if err != nil {
		return fmt.Errorf("failed to write file: %v", err)
	}
	
	// Silent success - file saved
	return nil
}
