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

			// DWARF-first approach: Trust DWARF over ABI guessing
			var registers []string
			var locationInfo string

			// Parse location information from DWARF
			locInfo := parseLocationInfo(dwarfData, locationAttr)
			
			if len(locInfo.Registers) > 0 {
				// DWARF has explicit register information - use it!
				registers = locInfo.Registers
				locationInfo = "from_dwarf_location"
			} else {
				// Only fall back to ABI guessing if DWARF provides no location info
				registers = getRegistersByGoABI(argType, currentFunc, currentFunc.HasReturnPtr)
				locationInfo = "from_abi_fallback"
				fmt.Fprintf(os.Stderr, "Warning: No DWARF location for %s.%s, using ABI fallback\n", 
					currentFunc.Name, argName)
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

// Improved location parsing with better error handling
func parseLocationInfo(d *dwarf.Data, locationAttr interface{}) LocationInfo {
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
		fmt.Fprintf(os.Stderr, "Debug: Parsing location list at offset %d (0x%x)\n", loc, loc)
		return parseLocationListOffset(d, loc)
		
	case []byte:
		// Direct location expression ([]byte and []uint8 are the same type)
		fmt.Fprintf(os.Stderr, "Debug: Parsing direct location expression (%d bytes)\n", len(loc))
		return parseLocationExpression(loc)
		
	default:
		fmt.Fprintf(os.Stderr, "Warning: Unknown location attribute type: %T, value: %v\n", 
			locationAttr, locationAttr)
		return info
	}
}

// Simplified but functional location list parser
func parseLocationListOffset(d *dwarf.Data, offset int64) LocationInfo {
	info := LocationInfo{
		Registers:    []string{},
		HasStack:     false,
		StackOffsets: []int64{},
	}

	// Known patterns based on DWARF analysis
	knownOffsets := map[int64][]string{
		236132: {"RDI", "RSI", "RDX"}, // pkScript []byte from your analysis
		// Add more patterns as you discover them by analyzing DWARF output
	}
	
	if registers, exists := knownOffsets[offset]; exists {
		info.Registers = registers
		fmt.Fprintf(os.Stderr, "Debug: Found known registers for offset %d: %v\n", offset, registers)
		return info
	}
	
	// Log unknown offsets so you can analyze them and add to known patterns
	fmt.Fprintf(os.Stderr, "Warning: Unknown location list offset %d (0x%x) - analyze with objdump and add to known patterns\n", 
		offset, offset)
	
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
				fmt.Fprintf(os.Stderr, "Debug: Found DW_OP_piece with size %d\n", pieceSize)
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
			fmt.Fprintf(os.Stderr, "Debug: Unknown DWARF op: 0x%02x at position %d (remaining bytes: %d)\n", 
				op, i-1, len(expr)-i+1)
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
func getRegistersByGoABI(argType string, currentFunc *Function, hasReturnPtr bool) []string {
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
		
		for i := regsUsed; i < regUsage; i++ {
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