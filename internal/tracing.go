// SPDX-License-Identifier: Apache-2.0
/* Copyright 2024 Authors of Cilium */

package internal

import (
	"fmt"
	"log"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sync/errgroup"
)

var TracepointMap = map[string]string{
	"nfs_readpage_done":  "nfs_read_done",
	"nfs_writeback_done": "nfs_write_done",
}

var TracepointProgs = map[string]string{
	"nfs_read_done":  "nfs_readpage_done",
	"nfs_write_done": "nfs_writeback_done",
}

type tracing struct {
	sync.Mutex
	links []link.Link
	progs []*ebpf.Program
}

func (t *tracing) HaveTracing() bool {
	t.Lock()
	defer t.Unlock()

	return len(t.links) > 0
}

func (t *tracing) Detach() {
	t.Lock()
	defer t.Unlock()

	t.detach()

	for _, p := range t.progs {
		_ = p.Close()
	}
	t.progs = nil
}

func (t *tracing) detach() {
	var errg errgroup.Group

	for _, l := range t.links {
		l := l
		errg.Go(func() error {
			_ = l.Close()
			return nil
		})
	}

	_ = errg.Wait()
}

func (t *tracing) addLink(l link.Link) {
	t.Lock()
	defer t.Unlock()

	t.links = append(t.links, l)
}

func (t *tracing) trace(tracingName string, prog *ebpf.Program) error {
	tracing, err := link.Tracepoint("nfs", tracingName, prog, nil)
	if err != nil {
		return fmt.Errorf("failed to attach tracing: %w", err)
	}

	t.addLink(tracing)

	return nil
}

func Tracepoint(progs map[string]*ebpf.Program) *tracing {
	log.Printf("Attaching TracePoint progs...\n")

	var t tracing
	for tragename, prog := range progs {
		if err := t.trace(tragename, prog); err != nil {
			log.Fatalf("failed to trace TracePoint progs: %v", err)
		}
	}

	return &t
}
