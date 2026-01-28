// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: ./panic-index [n]")
		return
	}

	n, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Println("Error: integer required")
		return
	}

	arr := []int{10, 20, 30}

	// Intentional out-of-bounds access when n == 3 or n < 0
	// This should lead to a runtime panic calling a panic index function.
	fmt.Println(arr[n])

	fmt.Println("OK")
}
