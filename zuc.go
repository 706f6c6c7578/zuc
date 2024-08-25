package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/emmansun/gmsm/zuc"
)

func main() {
	use256 := flag.Bool("256", false, "Use ZUC-256 instead of ZUC-128")
	flag.Parse()
	args := flag.Args()

	if len(args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s [-256] keyfile noncefile < infile > outfile\n", os.Args[0])
		os.Exit(1)
	}

	keyFile := args[0]
	nonceFile := args[1]

	var keySize, nonceSize int
	if *use256 {
		keySize = 32  // 256 bits = 32 bytes
		nonceSize = 23 // 184 bits = 23 bytes for ZUC-256
	} else {
		keySize = 16  // 128 bits = 16 bytes
		nonceSize = 16 // 128 bits = 16 bytes for ZUC-128
	}

	// Read key
	key, err := readHexFile(keyFile, keySize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading key file: %v\n", err)
		os.Exit(1)
	}

	// Read nonce (IV)
	nonce, err := readHexFile(nonceFile, nonceSize)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading nonce file: %v\n", err)
		os.Exit(1)
	}

	// Create ZUC cipher
	stream, err := zuc.NewCipher(key, nonce)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating ZUC cipher: %v\n", err)
		os.Exit(1)
	}

	// Process input
	buf := make([]byte, 4096)
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil && err != io.EOF {
			fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
			os.Exit(1)
		}
		if n == 0 {
			break
		}

		// XOR the input with the keystream
		stream.XORKeyStream(buf[:n], buf[:n])

		// Write the result to stdout
		_, err = os.Stdout.Write(buf[:n])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
			os.Exit(1)
		}
	}
}

func readHexFile(filename string, expectedBytes int) ([]byte, error) {
	content, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	// Remove any whitespace and convert to lowercase
	hexString := strings.TrimSpace(strings.ToLower(string(content)))

	// Decode the hex string
	decoded, err := hex.DecodeString(hexString)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string in file: %v", err)
	}

	// Check if the decoded length matches the expected length
	if len(decoded) != expectedBytes {
		return nil, fmt.Errorf("expected %d bytes, got %d bytes in %s", expectedBytes, len(decoded), filename)
	}

	return decoded, nil
}