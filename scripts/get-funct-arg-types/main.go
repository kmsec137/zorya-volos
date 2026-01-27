// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"debug/dwarf"
	"debug/elf"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// Controlled debug logging for DWARF/loclist parsing; enabled when
// GET_FUNCT_ARG_TYPES_DEBUG=1 in the environment.
var dwarfDebugEnabled = os.Getenv("GET_FUNCT_ARG_TYPES_DEBUG") == "1"

// Manual overrides for functions whose register usage is known to differ
// from ABI/DWARF-exposed locations (e.g., due to compiler/runtime conventions
// or p-code lowering differences).
var overrideRegs = map[string]map[string][]string{
	"runtime.timediv": {
		"v":   {"RAX"},
		"div": {"RBX"},
		"rem": {"RCX"},
		"~r0": {"RAX"},
	},
}

type Function struct {
	Name         string     `json:"name"`
	Address      string     `json:"address"`
	Arguments    []Argument `json:"arguments"`
	HasReturnPtr bool       `json:"has_return_ptr,omitempty"` // For debugging
}

type Argument struct {
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	Registers []string `json:"registers,omitempty"`
	Location  string   `json:"location,omitempty"` // For debugging location info
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func anyArgWithRegisters(args []Argument, regs []string) bool {
	for _, a := range args {
		if equalStringSlices(a.Registers, regs) {
			return true
		}
	}
	return false
}

// Prefer keeping a named argument; if a duplicate arrives with empty name and same regs, drop it.
func shouldSkipDuplicateArg(args []Argument, name, typ string, regs []string) bool {
	if len(regs) == 0 {
		return false
	}
	for _, a := range args {
		if equalStringSlices(a.Registers, regs) {
			// If existing arg has a name or same type, treat incoming as duplicate
			if a.Name != "" || a.Type == typ {
				return true
			}
		}
	}
	return false
}

// Standard x86-64 DWARF register mapping
var correctDwarfRegNames = map[int]string{
	0:  "RAX",
	1:  "RDX",
	2:  "RCX",
	3:  "RBX",
	4:  "RSI",
	5:  "RDI",
	6:  "RBP",
	7:  "RSP",
	8:  "R8",
	9:  "R9",
	10: "R10",
	11: "R11",
	12: "R12",
	13: "R13",
	14: "R14",
	15: "R15",
}

type LocationInfo struct {
	Registers    []string
	HasStack     bool
	StackOffsets []int64
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <binary_path> <output_path> [--extract-runtime-g]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		fmt.Fprintf(os.Stderr, "  --extract-runtime-g    Extract runtime.g struct offsets (saves to results/runtime_g_offsets.json)\n")
		os.Exit(1)
	}

	binaryPath := os.Args[1]
	outputPath := os.Args[2]
	
	// Check for --extract-runtime-g flag
	extractRuntimeG := false
	for _, arg := range os.Args[3:] {
		if arg == "--extract-runtime-g" {
			extractRuntimeG = true
		}
	}

	outputDir := filepath.Dir(outputPath)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	f, err := elf.Open(binaryPath)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	dwarfData, err := f.DWARF()
	if err != nil {
		log.Fatal(err)
	}
	
	// Extract runtime.g offsets if requested (for Go binaries)
	if extractRuntimeG {
		runtimeInfo, err := ExtractRuntimeGOffsets(dwarfData, binaryPath)
		if err != nil {
			// Silent - only show errors if debugging
			if os.Getenv("GET_FUNCT_ARG_TYPES_DEBUG") == "1" {
				fmt.Fprintf(os.Stderr, "[!] Could not extract runtime.g offsets: %v\n", err)
			}
		} else {
			runtimeOutputPath := filepath.Join(outputDir, "runtime_g_offsets.json")
			if err := SaveRuntimeGOffsets(runtimeInfo, runtimeOutputPath); err != nil {
				if os.Getenv("GET_FUNCT_ARG_TYPES_DEBUG") == "1" {
					fmt.Fprintf(os.Stderr, "[!] Could not save runtime.g offsets: %v\n", err)
				}
			}
		}
		
		// Reset DWARF reader for function signature extraction
		dwarfData, _ = f.DWARF()
	}

	functions := []Function{}
	rdr := dwarfData.Reader()

	var currentFunc *Function
	var currentFuncLowPC uint64
	safetyCounter := 0
	maxIterations := 100000

	for safetyCounter < maxIterations {
		safetyCounter++
		entry, err := rdr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		if entry == nil {
			continue
		}

		switch entry.Tag {
		case dwarf.TagSubprogram:
			if currentFunc != nil {
				functions = append(functions, *currentFunc)
			}

			funcName := ""
			var funcAddr uint64
			var returnType dwarf.Offset
			hasReturnType := false

			for _, field := range entry.Field {
				if field.Attr == dwarf.AttrName {
					funcName = field.Val.(string)
				}
				if field.Attr == dwarf.AttrLowpc {
					switch val := field.Val.(type) {
					case uint64:
						funcAddr = val
					case uintptr:
						funcAddr = uint64(val)
					}
				}
				if field.Attr == dwarf.AttrType {
					returnType = field.Val.(dwarf.Offset)
					hasReturnType = true
				}
			}

			if funcName != "" {
				// Check if the return type requires a pointer (RDI)
				hasReturnPtr := false
				if hasReturnType {
					hasReturnPtr = checkIfReturnTypeNeedsPointer(dwarfData, returnType)
				}

				currentFunc = &Function{
					Name:         funcName,
					Address:      fmt.Sprintf("0x%x", funcAddr),
					Arguments:    []Argument{},
					HasReturnPtr: hasReturnPtr,
				}
				currentFuncLowPC = funcAddr
			} else {
				currentFunc = nil
			}

		case dwarf.TagFormalParameter:
			if currentFunc == nil {
				continue
			}

			var argName string
			var argType string
			var locationAttr interface{}
			var isOutputParam bool // DW_AT_variable_parameter == 1 for Go result parameters (~r0, ~r1, ...)

			for _, field := range entry.Field {
				switch field.Attr {
				case dwarf.AttrName:
					argName = field.Val.(string)
				case dwarf.AttrType:
					typeOffset := field.Val.(dwarf.Offset)
					argType = fmt.Sprintf("type-offset-%d", typeOffset)

					func() {
						defer func() {
							if r := recover(); r != nil {
								fmt.Fprintf(os.Stderr, "Warning: Recovered from panic while resolving type: %v\n", r)
							}
						}()
						resolved := resolveTypeName(dwarfData, typeOffset)
						if resolved != "unknown" && resolved != "circular-reference" {
							argType = resolved
						}
					}()
				case dwarf.AttrLocation:
					locationAttr = field.Val
				case dwarf.AttrVarParam:
					// Go uses DW_AT_variable_parameter to mark *result* parameters (~r0, ~r1, ...)
					switch v := field.Val.(type) {
					case bool:
						isOutputParam = v
					case int64:
						isOutputParam = v != 0
					case uint64:
						isOutputParam = v != 0
					}
				}
			}

			// Skip Go result parameters: they are outputs (~r0, ~r1, offset, rest, ok, ...)
			// and should not be treated as *input* arguments in the JSON map that Zorya
			// uses for symbolic initialization.
			// We also defensively skip any synthetic "~r*" even if DW_AT_variable_parameter is missing.
			// see: https://github.com/golang/go/issues/21100 and https://github.com/golang/go/issues/59977
			if isOutputParam || strings.HasPrefix(argName, "~r") {
				continue
			}

			// Filter out ALL unnamed parameters early (before DWARF/ABI fallback warnings).
			// Go's compiler emits DWARF entries for internal temporaries, ABI slots, and
			// frame metadata that don't correspond to actual source parameters.
			if argName == "" {
				continue
			}

			// DWARF-first approach: Trust DWARF over ABI guessing
			var registers []string
			var locationInfo string

			// Parse location information from DWARF
			locInfo := parseLocationInfo(f, locationAttr, currentFuncLowPC)

			if len(locInfo.Registers) > 0 {
				// DWARF has explicit register information - use it.
				registers = locInfo.Registers
				locationInfo = "from_dwarf_location"
			} else {
				// DWARF does not describe an entry-location for this parameter; assign
				// registers/stack slots according to the Go ABI. This is a normal case
				// for many stdlib helpers and is not treated as a user-visible warning.
				registers = getRegistersByGoABI(argType, currentFunc)
				locationInfo = "abi_inferred"
			}

			// Apply manual overrides when present
			if ov, ok := overrideRegs[currentFunc.Name]; ok {
				if regs, ok2 := ov[argName]; ok2 && len(regs) > 0 {
					registers = regs
					locationInfo = "override"
				}
			}

			arg := Argument{
				Name:      argName,
				Type:      argType,
				Registers: registers,
			}

			// Enhanced debug location info
			if locationAttr != nil {
				arg.Location = fmt.Sprintf("%s: location_attr=%v (type:%T)",
					locationInfo, locationAttr, locationAttr)
			} else {
				arg.Location = locationInfo + ": no_location_attr"
			}

			// Deduplicate/merge: DWARF sometimes emits multiple formal params for slices/strings (pieces)
			// If an unnamed parameter arrives with identical register set (or same type), skip it.
			if shouldSkipDuplicateArg(currentFunc.Arguments, argName, argType, registers) {
				// Skip duplicate synthetic entry
				continue
			}

			currentFunc.Arguments = append(currentFunc.Arguments, arg)
		}
	}

	// Catch any remaining function
	if currentFunc != nil {
		// If overrides specify a synthetic return (~r0) and it's not present, add it
		if ov, ok := overrideRegs[currentFunc.Name]; ok {
			if regs, ok2 := ov["~r0"]; ok2 {
				found := false
				for _, a := range currentFunc.Arguments {
					if a.Name == "~r0" {
						found = true
						break
					}
				}
				if !found {
					currentFunc.Arguments = append(currentFunc.Arguments, Argument{
						Name:      "~r0",
						Type:      "int32",
						Registers: regs,
						Location:  "override",
					})
				}
			}
		}
		functions = append(functions, *currentFunc)
	}

	jsonData, err := json.MarshalIndent(functions, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile(outputPath, jsonData, 0644)
	if err != nil {
		log.Fatalf("Failed to write output file: %v", err)
	}
}

// Improved location parsing with better error handling
func parseLocationInfo(ef *elf.File, locationAttr interface{}, lowPC uint64) LocationInfo {
	info := LocationInfo{
		Registers:    []string{},
		HasStack:     false,
		StackOffsets: []int64{},
	}

	if locationAttr == nil {
		return info
	}

	switch loc := locationAttr.(type) {
	case int64:
		// Location list offset - this is the most common case for function parameters
		if dwarfDebugEnabled {
			fmt.Fprintf(os.Stderr, "Debug: Parsing location list at offset %d (0x%x)\n", loc, loc)
		}
		// Try DWARF v5 .debug_loclists first, then legacy .debug_loc
		if ef.Section(".debug_loclists") != nil && ef.Section(".debug_loclists").Size > 0 {
			parsed := parseLocationListOffsetV5(ef, uint64(loc), lowPC)
			if len(parsed.Registers) > 0 || len(parsed.StackOffsets) > 0 {
				return normalizeStackRegisters(parsed)
			}
		}
		if ef.Section(".debug_loc") != nil && ef.Section(".debug_loc").Size > 0 {
			parsed := parseLocationListOffsetLegacy(ef, uint64(loc), lowPC)
			return normalizeStackRegisters(parsed)
		}
		// Many binaries (or specific compilers) legitimately omit loclists sections;
		// this is not an error for our use-case, so only surface it in debug mode.
		if dwarfDebugEnabled {
			fmt.Fprintf(os.Stderr, "Warning: No loclists sections present in ELF\n")
		}
		return info

	case []byte:
		// Direct location expression ([]byte and []uint8 are the same type)
		if dwarfDebugEnabled {
			fmt.Fprintf(os.Stderr, "Debug: Parsing direct location expression (%d bytes)\n", len(loc))
		}
		return normalizeStackRegisters(parseLocationExpression(loc))

	default:
		fmt.Fprintf(os.Stderr, "Warning: Unknown location attribute type: %T, value: %v\n",
			locationAttr, locationAttr)
		return info
	}
}

// Normalize stack-related placeholders into explicit strings usable by the Rust side.
func normalizeStackRegisters(in LocationInfo) LocationInfo {
	if len(in.Registers) == 0 {
		return in
	}
	// Replace STACK/FRAME_BASE with STACK+0x<offset> if we have corresponding offsets
	out := LocationInfo{Registers: []string{}, HasStack: in.HasStack, StackOffsets: in.StackOffsets}
	offsetIdx := 0
	for _, r := range in.Registers {
		switch r {
		case "STACK", "FRAME_BASE":
			if offsetIdx < len(in.StackOffsets) {
				out.Registers = append(out.Registers, fmt.Sprintf("STACK+0x%x", uint64(in.StackOffsets[offsetIdx])))
				offsetIdx++
			} else {
				out.Registers = append(out.Registers, r)
			}
		default:
			out.Registers = append(out.Registers, r)
		}
	}
	return out
}

// Parse legacy DWARF location lists (.debug_loc, DWARF <= v4)
func parseLocationListOffsetLegacy(ef *elf.File, offset uint64, lowPC uint64) LocationInfo {
	info := LocationInfo{Registers: []string{}, HasStack: false, StackOffsets: []int64{}}

	sec := ef.Section(".debug_loc")
	if sec == nil || sec.Size == 0 {
		return info
	}
	data, err := sec.Data()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to read .debug_loc: %v\n", err)
		return info
	}
	if offset >= uint64(len(data)) {
		fmt.Fprintf(os.Stderr, "Warning: .debug_loc offset out of range: 0x%x\n", offset)
		return info
	}

	addrSize := 8
	is64 := ef.Class == elf.ELFCLASS64
	if !is64 {
		addrSize = 4
	}
	order := ef.ByteOrder

	i := int(offset)
	var base uint64 = 0
	// Base address selection markers per DWARF spec
	var baseMarker uint64 = 0xffffffff
	if is64 {
		baseMarker = 0xffffffffffffffff
	}

	for i < len(data) {
		// Read start, end
		if i+addrSize*2 > len(data) {
			break
		}
		var start, end uint64
		if addrSize == 8 {
			start = order.Uint64(data[i : i+8])
			end = order.Uint64(data[i+8 : i+16])
			i += 16
		} else {
			start = uint64(order.Uint32(data[i : i+4]))
			end = uint64(order.Uint32(data[i+4 : i+8]))
			i += 8
		}

		if start == 0 && end == 0 {
			// End of list
			break
		}
		if start == baseMarker {
			// Base address selection entry
			base = end
			continue
		}

		// Expression length (u16), then bytes
		if i+2 > len(data) {
			break
		}
		exprLen := int(order.Uint16(data[i : i+2]))
		i += 2
		if i+exprLen > len(data) {
			break
		}
		expr := data[i : i+exprLen]
		i += exprLen

		// Compute absolute range
		absStart := start
		absEnd := end
		if base != 0 {
			absStart = base + start
			absEnd = base + end
		}
		if lowPC >= absStart && lowPC < absEnd {
			// This is the location at function entry
			return parseLocationExpression(expr)
		}
	}
	return info
}

// Parse DWARF v5 location lists (.debug_loclists)
func parseLocationListOffsetV5(ef *elf.File, offset uint64, lowPC uint64) LocationInfo {
	info := LocationInfo{Registers: []string{}, HasStack: false, StackOffsets: []int64{}}

	sec := ef.Section(".debug_loclists")
	if sec == nil || sec.Size == 0 {
		return info
	}
	data, err := sec.Data()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to read .debug_loclists: %v\n", err)
		return info
	}
	if offset >= uint64(len(data)) {
		fmt.Fprintf(os.Stderr, "Warning: .debug_loclists offset out of range: 0x%x\n", offset)
		return info
	}

	addrSize := 8
	if ef.Class != elf.ELFCLASS64 {
		addrSize = 4
	}
	order := ef.ByteOrder

	// In v5, the offset can be either an index into an offset table or a direct sec offset.
	// We assume a direct section offset to the start of a location list for simplicity.
	i := int(offset)
	var base uint64 = 0

	// Helper to read an address
	readAddr := func() (uint64, bool) {
		if i+addrSize > len(data) {
			return 0, false
		}
		var v uint64
		if addrSize == 8 {
			v = order.Uint64(data[i : i+8])
		} else {
			v = uint64(order.Uint32(data[i : i+4]))
		}
		i += addrSize
		return v, true
	}

	for i < len(data) {
		kind := data[i]
		i++
		switch kind {
		case 0x00: // DW_LLE_end_of_list
			return info
		case 0x01: // DW_LLE_base_addressx - base address from .debug_addr via index
			// Read ULEB128 index into .debug_addr
			idx, n := readULEB128(data[i:])
			i += n
			// We don't have access to .debug_addr here, so we can't resolve the actual address
			// Just use the index as a placeholder - the important part is the offset pairs that follow
			if dwarfDebugEnabled {
				fmt.Fprintf(os.Stderr, "Debug: DW_LLE_base_addressx with index %d (address lookup not implemented)\n", idx)
			}
			// Continue parsing - the offset pairs will be relative to this base
			
		case 0x02: // DW_LLE_startx_endx - start and end from .debug_addr via indices
			// Read ULEB128 start index
			startIdx, n1 := readULEB128(data[i:])
			i += n1
			// Read ULEB128 end index
			endIdx, n2 := readULEB128(data[i:])
			i += n2
			// Read expression length and expression
			if i >= len(data) {
				return info
			}
			exprLen, n3 := readULEB128(data[i:])
			i += n3
			if i+int(exprLen) > len(data) {
				return info
			}
			expr := data[i : i+int(exprLen)]
			i += int(exprLen)
			if dwarfDebugEnabled {
				fmt.Fprintf(os.Stderr, "Debug: DW_LLE_startx_endx with indices %d-%d (parsing expression anyway)\n", startIdx, endIdx)
			}
			// Can't check address range without .debug_addr, but return the expression anyway
			// as it's likely the first entry for the function
			return parseLocationExpression(expr)
			
		case 0x03: // DW_LLE_startx_length - start from .debug_addr via index, length as ULEB
			// Read ULEB128 start index
			startIdx, n1 := readULEB128(data[i:])
			i += n1
			// Read ULEB128 length
			length, n2 := readULEB128(data[i:])
			i += n2
			// Read expression
			if i >= len(data) {
				return info
			}
			exprLen, n3 := readULEB128(data[i:])
			i += n3
			if i+int(exprLen) > len(data) {
				return info
			}
			expr := data[i : i+int(exprLen)]
			i += int(exprLen)
			if dwarfDebugEnabled {
				fmt.Fprintf(os.Stderr, "Debug: DW_LLE_startx_length with index %d, length %d (parsing expression anyway)\n", startIdx, length)
			}
			return parseLocationExpression(expr)
			
		case 0x04: // DW_LLE_offset_pair - offsets from base address
			startOff, n1 := readULEB128(data[i:])
			i += n1
			endOff, n2 := readULEB128(data[i:])
			i += n2
			exprLen, n3 := readULEB128(data[i:])
			i += n3
			if i+int(exprLen) > len(data) {
				return info
			}
			expr := data[i : i+int(exprLen)]
			i += int(exprLen)
			// For offset pairs, we need a base address
			// If we parsed a base_addressx before, we can't resolve it without .debug_addr
			// But we can still return the expression as it's the register location
			if dwarfDebugEnabled {
				fmt.Fprintf(os.Stderr, "Debug: DW_LLE_offset_pair with offsets 0x%x-0x%x (base=0x%x)\n", startOff, endOff, base)
			}
			// Return the expression anyway - it contains the register information
			return parseLocationExpression(expr)
			
		case 0x06: // DW_LLE_base_address - absolute base address
			v, ok := readAddr()
			if !ok {
				return info
			}
			base = v
			
		case 0x07: // DW_LLE_start_end - absolute start and end addresses
			start, ok1 := readAddr()
			end, ok2 := readAddr()
			if !ok1 || !ok2 {
				return info
			}
			if i >= len(data) {
				return info
			}
			exprLen, n := readULEB128(data[i:])
			i += n
			if i+int(exprLen) > len(data) {
				return info
			}
			expr := data[i : i+int(exprLen)]
			i += int(exprLen)
			if lowPC >= start && lowPC < end {
				return parseLocationExpression(expr)
			}
			
		case 0x08: // DW_LLE_start_length - absolute start address and length
			start, ok := readAddr()
			if !ok {
				return info
			}
			length, n := readULEB128(data[i:])
			i += n
			if i >= len(data) {
				return info
			}
			exprLen, n2 := readULEB128(data[i:])
			i += n2
			if i+int(exprLen) > len(data) {
				return info
			}
			expr := data[i : i+int(exprLen)]
			i += int(exprLen)
			end := start + length
			if lowPC >= start && lowPC < end {
				return parseLocationExpression(expr)
			}
			
		default:
			// Unknown kind
			if dwarfDebugEnabled {
				fmt.Fprintf(os.Stderr, "Debug: Unknown DW_LLE kind 0x%02x at offset 0x%x\n", kind, i-1)
			}
			return info
		}
	}
	return info
}

// Enhanced location expression parser with better bounds checking
func parseLocationExpression(expr []byte) LocationInfo {
	info := LocationInfo{
		Registers:    []string{},
		HasStack:     false,
		StackOffsets: []int64{},
	}

	if len(expr) == 0 {
		return info
	}

	i := 0
	for i < len(expr) {
		op := expr[i]
		i++

		switch op {
		// DW_OP_reg0 through DW_OP_reg15
		case 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f:
			regNum := int(op - 0x50)
			if regName, exists := correctDwarfRegNames[regNum]; exists {
				info.Registers = append(info.Registers, regName)
			}

		// DW_OP_breg0 through DW_OP_breg15 (register + offset)
		case 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f:
			regNum := int(op - 0x70)
			if i < len(expr) {
				offset, bytesRead := readLEB128(expr[i:])
				i += bytesRead

				info.HasStack = true
				info.StackOffsets = append(info.StackOffsets, offset)

				if regNum == 7 { // RSP
					info.Registers = append(info.Registers, "STACK")
				} else if regName, exists := correctDwarfRegNames[regNum]; exists {
					info.Registers = append(info.Registers, regName)
				}
			}

		// DW_OP_piece - indicates multi-part values
		case 0x93:
			if i < len(expr) {
				pieceSize, bytesRead := readULEB128(expr[i:])
				i += bytesRead
				if dwarfDebugEnabled {
					fmt.Fprintf(os.Stderr, "Debug: Found DW_OP_piece with size %d\n", pieceSize)
				}
			}

		// DW_OP_regx - register with ULEB128 number
		case 0x90:
			if i < len(expr) {
				regNum, bytesRead := readULEB128(expr[i:])
				i += bytesRead
				if regName, exists := correctDwarfRegNames[int(regNum)]; exists {
					info.Registers = append(info.Registers, regName)
				}
			}

		// DW_OP_fbreg - frame base register + offset
		case 0x91:
			if i < len(expr) {
				offset, bytesRead := readLEB128(expr[i:])
				i += bytesRead
				info.HasStack = true
				info.StackOffsets = append(info.StackOffsets, offset)
				info.Registers = append(info.Registers, "FRAME_BASE")
			}

		// DW_OP_bregx - register + offset with ULEB128 register number
		case 0x92:
			if i < len(expr) {
				regNum, bytesRead1 := readULEB128(expr[i:])
				i += bytesRead1
				if i < len(expr) {
					offset, bytesRead2 := readLEB128(expr[i:])
					i += bytesRead2

					info.HasStack = true
					info.StackOffsets = append(info.StackOffsets, offset)

					if regNum == 7 { // RSP
						info.Registers = append(info.Registers, "STACK")
					} else if regName, exists := correctDwarfRegNames[int(regNum)]; exists {
						info.Registers = append(info.Registers, regName)
					}
				}
			}

		default:
			// Skip unknown operations - but don't crash
			if dwarfDebugEnabled {
				fmt.Fprintf(os.Stderr, "Debug: Unknown DWARF op: 0x%02x at position %d (remaining bytes: %d)\n",
					op, i-1, len(expr)-i+1)
			}
		}

		// Safety check to prevent infinite loops
		if i > len(expr) {
			fmt.Fprintf(os.Stderr, "Warning: DWARF expression parser went beyond bounds, stopping\n")
			break
		}
	}

	return info
}

// Helper functions for LEB128 decoding with bounds checking
func readULEB128(data []byte) (uint64, int) {
	if len(data) == 0 {
		return 0, 0
	}

	var result uint64
	var shift uint
	var i int

	for i = 0; i < len(data); i++ {
		b := data[i]
		result |= uint64(b&0x7F) << shift
		if (b & 0x80) == 0 {
			break
		}
		shift += 7
		if shift >= 64 {
			// Prevent overflow
			break
		}
	}

	return result, i + 1
}

func readLEB128(data []byte) (int64, int) {
	if len(data) == 0 {
		return 0, 0
	}

	var result int64
	var shift uint
	var i int

	for i = 0; i < len(data); i++ {
		b := data[i]
		result |= int64(b&0x7F) << shift
		shift += 7
		if (b & 0x80) == 0 {
			break
		}
		if shift >= 64 {
			// Prevent overflow
			break
		}
	}

	// Sign extend if necessary
	if i < len(data) && shift < 64 && (data[i]&0x40) != 0 {
		result |= -(1 << shift)
	}

	return result, i + 1
}

// Check if the return type needs a pointer in RDI
func checkIfReturnTypeNeedsPointer(d *dwarf.Data, offset dwarf.Offset) bool {
	r := d.Reader()
	r.Seek(offset)
	entry, err := r.Next()
	if err != nil || entry == nil {
		return false
	}

	// First check if we can get the type name directly
	var typeName string
	for _, f := range entry.Field {
		if f.Attr == dwarf.AttrName {
			typeName = f.Val.(string)
			break
		}
	}

	// If we have a type name, check if it's a complex Go type
	if typeName != "" {
		if isComplexGoType(typeName) {
			return true
		}
	}

	// Check the type tag to determine if it needs a return pointer
	switch entry.Tag {
	case dwarf.TagStructType:
		return true
	case dwarf.TagArrayType:
		return true
	case dwarf.TagStringType:
		return true
	case dwarf.TagInterfaceType:
		return true
	case dwarf.TagPointerType:
		return false
	case dwarf.TagBaseType:
		var byteSize int64 = 0
		for _, f := range entry.Field {
			if f.Attr == dwarf.AttrByteSize {
				switch size := f.Val.(type) {
				case int64:
					byteSize = size
				case uint64:
					byteSize = int64(size)
				}
				break
			}
		}
		return byteSize > 8
	case dwarf.TagTypedef:
		for _, f := range entry.Field {
			if f.Attr == dwarf.AttrType {
				underlyingType := f.Val.(dwarf.Offset)
				return checkIfReturnTypeNeedsPointer(d, underlyingType)
			}
		}
		return false
	default:
		return true
	}
}

// Check if a Go type name indicates a complex type that needs a return pointer
func isComplexGoType(typeName string) bool {
	if strings.Contains(typeName, "[]") { // slices
		return true
	}
	if strings.HasPrefix(typeName, "map[") { // maps
		return true
	}
	if strings.Contains(typeName, "interface") || strings.Contains(typeName, "any") { // interfaces
		return true
	}
	if strings.HasPrefix(typeName, "[") && strings.Contains(typeName, "]") && !strings.Contains(typeName, "byte") {
		return true
	}
	return false
}

// Fallback ABI guessing - only used when DWARF provides no location info
func getRegistersByGoABI(argType string, currentFunc *Function) []string {
	// For TinyGo: Use LLVM-style register assignment
	// Don't make assumptions about return pointer reservation - trust DWARF instead
	intRegs := []string{"RDI", "RSI", "RDX", "RCX", "R8", "R9"}

	// Calculate register usage for current argument
	regUsage := calculateRegisterUsage(argType)

	// Calculate starting register position based on previous arguments
	startReg := calculateStartingRegisterAccurate(currentFunc.Arguments)

	if startReg >= len(intRegs) {
		// Arguments go to stack
		stackOffsets := make([]string, regUsage)
		for i := 0; i < regUsage; i++ {
			offset := 8 + (startReg-len(intRegs)+i)*8
			stackOffsets[i] = fmt.Sprintf("STACK+0x%x", offset)
		}
		return stackOffsets
	}

	endReg := startReg + regUsage
	if endReg > len(intRegs) {
		// Partially on stack
		regsUsed := len(intRegs) - startReg
		result := make([]string, regUsage)
		copy(result, intRegs[startReg:])

		for i := regsUsed; i < regUsage; i++ {
			stackOffset := 8 + (i-regsUsed)*8
			result[i] = fmt.Sprintf("STACK+0x%x", stackOffset)
		}
		return result
	}

	result := make([]string, regUsage)
	copy(result, intRegs[startReg:endReg])
	return result
}

// Calculate the starting register for an argument based on actual previous arguments
func calculateStartingRegisterAccurate(previousArgs []Argument) int {
	totalRegsUsed := 0

	// Sum up the register usage of all previous arguments
	for _, arg := range previousArgs {
		regUsage := calculateRegisterUsage(arg.Type)
		totalRegsUsed += regUsage
	}

	return totalRegsUsed
}

func calculateRegisterUsage(typ string) int {
	typ = strings.TrimSpace(typ)
	switch {
	case typ == "string":
		return 2 // ptr + len
	case strings.HasPrefix(typ, "[]"):
		return 3 // ptr + len + cap
	case strings.Contains(typ, "interface") || strings.Contains(typ, "any"):
		return 2 // interface data + type
	case strings.HasPrefix(typ, "[") && strings.Contains(typ, "]"):
		// Array type - size depends on actual array size, but typically passed by reference
		return 1 // pointer to array
	default:
		return 1 // scalar values
	}
}

func resolveTypeName(d *dwarf.Data, offset dwarf.Offset) string {
	r := d.Reader()
	r.Seek(offset)
	entry, err := r.Next()
	if err != nil || entry == nil {
		return "unknown"
	}

	for _, f := range entry.Field {
		if f.Attr == dwarf.AttrName {
			return f.Val.(string)
		}
	}

	var typeOffset dwarf.Offset
	for _, f := range entry.Field {
		if f.Attr == dwarf.AttrType {
			typeOffset = f.Val.(dwarf.Offset)
			if offset == typeOffset {
				return "circular-reference"
			}
			return resolveTypeName(d, typeOffset)
		}
	}

	switch entry.Tag {
	case dwarf.TagBaseType:
		return "base-type"
	case dwarf.TagPointerType:
		return "pointer"
	case dwarf.TagArrayType:
		return "array"
	case dwarf.TagStructType:
		return "struct"
	default:
		return fmt.Sprintf("unknown-tag-%d", entry.Tag)
	}
}
