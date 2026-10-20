// Command ledgerctl provides offline WAL maintenance and verified backups.
// Backup and compaction require an exclusive journal lock (stop the server).
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"cloudruntimeguardian/internal/journal"
	"cloudruntimeguardian/internal/snapshot"
)

func main() {
	data := flag.String("data", "./data/journal.jsonl", "path to the ledger")
	capacity := flag.Int("max-records", 2000000, "maximum records allowed during replay")
	compact := flag.Bool("compact-closed", false, "losslessly gzip closed WAL segments")
	backup := flag.String("snapshot", "", "create an offline verifiable snapshot ZIP at this path (must not exist)")
	verify := flag.String("verify-snapshot", "", "verify snapshot ZIP without writing data")
	restore := flag.String("restore-snapshot", "", "restore this snapshot ZIP into -restore-dir")
	restoreDir := flag.String("restore-dir", "", "new, nonexistent directory for restored ledger")
	prune := flag.String("prune-snapshots-dir", "", "remove older verified crg-*.crg-snapshot.zip backup archives only")
	keep := flag.Int("keep-snapshots", 3, "number of verified backup archives to retain (minimum 2)")
	flag.Parse()
	if *capacity < 1 || *capacity > 10000000 {
		log.Fatal("max-records must be 1..10000000")
	}
	modes := 0
	for _, enabled := range []bool{*backup != "", *verify != "", *restore != "", *prune != "", *compact} {
		if enabled {
			modes++
		}
	}
	if modes > 1 {
		log.Fatal("choose only one maintenance operation")
	}
	if *restore != "" {
		if *restoreDir == "" {
			log.Fatal("-restore-dir required")
		}
		m, err := snapshot.Restore(*restore, *restoreDir, *capacity)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Restored %d committed records into %s (verify archive integrity and WAL replay passed)\n", m.RecordCount, *restoreDir)
		return
	}
	if *verify != "" {
		m, err := snapshot.Verify(*verify)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Snapshot verified: %d files, %d records; to validate WAL replay use -restore-snapshot with a new restore directory\n", len(m.Files), m.RecordCount)
		return
	}
	if *prune != "" {
		n, err := snapshot.Prune(*prune, *keep)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Deleted %d old, verified backup archives; authoritative WAL remains intact\n", n)
		return
	}
	if *backup != "" {
		m, err := snapshot.Create(*data, *backup, *capacity)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Created offline snapshot: %d files, %d journal records; original WAL unchanged\n", len(m.Files), m.RecordCount)
		return
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
