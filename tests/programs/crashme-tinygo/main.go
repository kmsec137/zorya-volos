// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
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
