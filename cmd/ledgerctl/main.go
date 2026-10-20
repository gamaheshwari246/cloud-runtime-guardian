// Command ledgerctl runs offline WAL verification and lossless compression.
// The server must be stopped: the exclusive journal lock enforces this.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"cloudruntimeguardian/internal/journal"
)

func main() {
	data := flag.String("data", "./data/journal.jsonl", "path to the ledger")
	capacity := flag.Int("max-records", 2000000, "upper limit for replay record count")
	compact := flag.Bool("compact-closed", false, "gzip closed numbered WAL segments (does not delete history)")
	flag.Parse()
	if *capacity < 1 || *capacity > 10000000 {
		log.Fatal("max-records must be between 1 and 10000000")
	}
	j, entries, err := journal.Open(*data, *capacity)
	if err != nil {
		log.Fatalf("verify ledger: %v", err)
	}
	defer j.Close()
	fmt.Fprintf(os.Stdout, "Verified %d committed records\n", len(entries))
	if *compact {
		n, err := j.CompactClosed()
		if err != nil {
			log.Fatalf("compact closed WAL segments: %v", err)
		}
		fmt.Fprintf(os.Stdout, "Compressed %d closed segments; records and event IDs retained\n", n)
	}
}
