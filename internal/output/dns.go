package output

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/cen-ngc5139/nfs-trace/internal/binary"
	"github.com/cen-ngc5139/nfs-trace/internal/bpf"
	"github.com/cen-ngc5139/nfs-trace/internal/log"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

func ProcessDNS(coll *ebpf.Collection, ctx context.Context, flag *bpf.Flags) {
	events := coll.Maps["dns_events"]
	// Set up a perf reader to read events from the eBPF program
	rd, err := perf.NewReader(events, os.Getpagesize())
	if err != nil {
		log.Fatalf("Creating perf reader failed: %v\n", err)
	}
	defer rd.Close()

	var event binary.KProbePWRUDnsEvent
	for {
		for {
			if err := parseEvent(rd, &event); err == nil {
				break
			}

			select {
			case <-ctx.Done():
				log.Infof("退出 DNS 处理")
				return
			case <-time.After(time.Microsecond):
				continue
			}
		}

		dname := ParseDNS(event.Domain[:])
		comm := convertInt8ToString(event.Common[:])
		if len(dname) != 0 {
			log.StdoutOrFile(flag.OutputType, map[string]interface{}{
				"pid":    event.Pid,
				"comm":   comm,
				"domain": dname,
			})
		}

		select {
		case <-ctx.Done():
			log.Infof("退出 DNS 处理")
			return
		default:
		}
	}
}

func ParseDNS(bs []int8) string {
	raw := convertInt8ToBytes(bs)
	return parseDNSDomain(raw)
}

func convertInt8ToBytes(bs []int8) []byte {
	ba := make([]byte, 0, len(bs))
	for _, b := range bs {
		ba = append(ba, byte(b))
	}
	return ba
}

// parseDNSDomain parses a DNS domain from a DNS query.
func parseDNSDomain(query []byte) string {
	var domain strings.Builder
	for len(query) > 0 {
		length := int(query[0])
		if length == 0 {
			break
		}
		if len(query) < length+1 {
			break
		}
		domain.WriteString(string(query[1:length+1]) + ".")
		query = query[length+1:]
	}
	// Remove the trailing dot
	return strings.TrimSuffix(domain.String(), ".")
}
