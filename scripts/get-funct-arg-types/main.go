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
	Registers []string
	HasStack  bool
	StackOffsets []int64
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <binary_path> <output_path>\n", os.Args[0])
		os.Exit(1)
	}

	binaryPath := os.Args[1]
	outputPath := os.Args[2]

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

	functions := []Function{}
	rdr := dwarfData.Reader()

	var currentFunc *Function
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
				}
			}

			// Parse location information from DWARF
			locInfo := parseLocationInfo(dwarfData, locationAttr)
			
			// Apply specific knowledge for known functions
			registers := locInfo.Registers
			if len(registers) == 0 {
				registers = getRegistersByGoABI(argType, currentFunc, currentFunc.HasReturnPtr)
			}
			
			arg := Argument{
				Name:      argName,
				Type:      argType,
				Registers: registers,
			}

			// Add debug location info
			if locationAttr != nil {
				arg.Location = fmt.Sprintf("location_attr: %v (type: %T)", locationAttr, locationAttr)
			}

			currentFunc.Arguments = append(currentFunc.Arguments, arg)
		}
	}

	// Catch any remaining function
	if currentFunc != nil {
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

	fmt.Fprintf(os.Stderr, "Successfully wrote JSON data to %s (%d bytes)\n", outputPath, len(jsonData))
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
		// Structs typically need return pointers
		return true
	case dwarf.TagArrayType:
		// Arrays typically need return pointers
		return true
	case dwarf.TagStringType:
		// Go strings need return pointers
		return true
	case dwarf.TagInterfaceType:
		// Go interfaces need return pointers
		return true
	case dwarf.TagPointerType:
		// Simple pointers usually don't need return pointer (they fit in a register)
		return false
	case dwarf.TagBaseType:
		// Check the size of the base type
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
		// If the type is larger than 8 bytes (register size), it needs a return pointer
		return byteSize > 8
	case dwarf.TagTypedef:
		// For typedefs, we need to check the underlying type
		for _, f := range entry.Field {
			if f.Attr == dwarf.AttrType {
				underlyingType := f.Val.(dwarf.Offset)
				return checkIfReturnTypeNeedsPointer(d, underlyingType)
			}
		}
		return false
	default:
		// For unknown types, be conservative and assume they might need a return pointer
		// This is safer than assuming they don't
		return true
	}
}

// Check if a Go type name indicates a complex type that needs a return pointer
func isComplexGoType(typeName string) bool {
	// Go types that typically need return pointers
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
		// Large arrays (but not byte arrays which might be small)
		return true
	}
	// Struct types usually need return pointers unless they're very simple
	// This is a heuristic - you might need to adjust based on your specific use case
	return false
}

func parseLocationInfo(d *dwarf.Data, locationAttr interface{}) LocationInfo {
	info := LocationInfo{
		Registers: []string{},
		HasStack:  false,
		StackOffsets: []int64{},
	}

	if locationAttr == nil {
		return info
	}

	// Handle location list offset
	switch loc := locationAttr.(type) {
	case int64:
		// This is a location list offset - we need to read the location list
		return parseLocationFromOffset(d, loc)
	case []byte:
		// This is a location expression
		return parseLocationExpression(loc)
	default:
		fmt.Fprintf(os.Stderr, "Unknown location type: %T\n", locationAttr)
		return info
	}
}

func parseLocationFromOffset(d *dwarf.Data, offset int64) LocationInfo {
	info := LocationInfo{
		Registers: []string{},
		HasStack:  false,
		StackOffsets: []int64{},
	}
	// TODO: read the .debug_loc section and parse the location lists properly
	
	return info
}

func parseLocationExpression(expr []byte) LocationInfo {
	info := LocationInfo{
		Registers: []string{},
		HasStack:  false,
		StackOffsets: []int64{},
	}

	i := 0
	for i < len(expr) {
		op := expr[i]
		i++

		switch op {
		case 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f:
			// DW_OP_reg0 through DW_OP_reg15
			regNum := int(op - 0x50)
			if regName, exists := correctDwarfRegNames[regNum]; exists {
				info.Registers = append(info.Registers, regName)
			}
		case 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f:
			// DW_OP_breg0 through DW_OP_breg15 (register + offset)
			regNum := int(op - 0x70)
			if i < len(expr) {
				// Read LEB128 offset (simplified - just read one byte for now)
				offset := int64(int8(expr[i]))
				i++
				info.HasStack = true
				info.StackOffsets = append(info.StackOffsets, offset)
				if regNum == 7 { // RSP
					info.Registers = append(info.Registers, "STACK")
				}
			}
		case 0x93: // DW_OP_piece
			// Skip piece size (LEB128)
			if i < len(expr) {
				i++ // Simplified - just skip one byte
			}
		}
	}

	return info
}

// Go ABI register assignment with return pointer consideration
func getRegistersByGoABI(argType string, currentFunc *Function, hasReturnPtr bool) []string {
	// Go ABI register order for integer arguments
	intRegs := []string{"RDI", "RSI", "RDX", "RCX", "R8", "R9"}
	
	// If function has a return pointer, RDI is reserved, so arguments start from RSI
	if hasReturnPtr {
		intRegs = []string{"RSI", "RDX", "RCX", "R8", "R9"}
	}
	
	// Calculate register usage for current argument
	regUsage := calculateRegisterUsage(argType)
	
	// Calculate starting register position based on actual previous arguments
	startReg := calculateStartingRegisterAccurate(currentFunc.Arguments)
	
	if startReg >= len(intRegs) {
		// All arguments go to stack
		stackOffsets := make([]string, regUsage)
		for i := 0; i < regUsage; i++ {
			// Stack starts at 0x8 due to return address, then each register slot is 8 bytes
			offset := 8 + (startReg - len(intRegs) + i) * 8
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
		
		// Add stack locations for remaining registers
		for i := regsUsed; i < regUsage; i++ {
			// Stack starts at 0x8 due to return address
			stackOffset := 8 + (i - regsUsed) * 8
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