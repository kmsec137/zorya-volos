// SPDX-FileCopyrightText: 2026 Keith Makan Security Consultancy Pty Ltd - WORLD CLASS CYBERSECURITY
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: ./crashme [char]")
		return
	}
	if os.Args[1][0] == 'K' {
		var p *int
		*p = 0
	}
	fmt.Println("OK")
}
