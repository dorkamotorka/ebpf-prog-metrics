package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go exporter metrics.c

import (
	"bufio"
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const (
	UPDATE_INTERVAL = 1 // sec
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	objs := exporterObjects{}
	if err := loadExporterObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load objects: %v", err)
	}
	defer objs.Close()

	// Attach the program to the Iterator hook.
	iterLink, err := link.AttachIter(link.IterOptions{
		Program: objs.DumpBpfProg,
	})
	if err != nil {
		log.Fatalf("Failed to attach eBPF program: %v", err)
	}
	defer iterLink.Close()
	log.Println("eBPF program attached successfully.")

	// Keep the program running.
	for {
		time.Sleep(UPDATE_INTERVAL * time.Second)
		reader, err := iterLink.Open()
		if err != nil {
			log.Fatalf("Failed to open BPF iterator: %v", err)
		}
		defer reader.Close()

		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			// Parse the line
			line := scanner.Text()
			fmt.Printf("%s\n", line)
		}

		if err := scanner.Err(); err != nil {
			log.Fatal(err)
		}
	}
}
