package internal

import (
	"fmt"
	"github.com/cilium/ebpf/btf"
	"k8s.io/klog/v2"
	"log"
	"os"
	"path/filepath"
	"regexp"
)

type Funcs map[string]int

func (f Funcs) ToString() {
	for mod, index := range f {
		klog.Infof("%s %d", mod, index)
	}
}

func GetFuncs(pattern, filterStruct string, spec *btf.Spec, kmods []string, kprobeMulti bool) (funcs Funcs, err error) {
	funcs = Funcs{}
	type iterator struct {
		kmod string
		iter *btf.TypesIterator
	}

	reg, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regular expression %v", err)
	}

	var availableFuncs map[string]struct{}
	if kprobeMulti {
		availableFuncs, err = getAvailableFilterFunctions()
		if err != nil {
			log.Printf("Failed to retrieve available ftrace functions (is /sys/kernel/debug/tracing mounted?): %s", err)
		}
	}

	iters := []iterator{{"", spec.Iterate()}}
	for _, module := range kmods {
		path := filepath.Join("/sys/kernel/btf", module)
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("failed to open %s: %v", path, err)
		}
		defer f.Close()

		modSpec, err := btf.LoadSplitSpecFromReader(f, spec)
		if err != nil {
			return nil, fmt.Errorf("failed to load %s btf: %v", module, err)
		}
		iters = append(iters, iterator{module, modSpec.Iterate()})
	}

	for _, it := range iters {
		for it.iter.Next() {
			typ := it.iter.Type
			fn, ok := typ.(*btf.Func)
			if !ok {
				continue
			}

			fnName := fn.Name

			if pattern != "" && reg.FindString(fnName) != fnName {
				continue
			}

			if kprobeMulti {
				availableFnName := fnName
				if it.kmod != "" {
					availableFnName = fmt.Sprintf("%s [%s]", fnName, it.kmod)
				}
				if _, ok := availableFuncs[availableFnName]; !ok {
					continue
				}
			}

			fnProto := fn.Type.(*btf.FuncProto)
			i := 1
			for _, p := range fnProto.Params {
				if ptr, ok := p.Type.(*btf.Pointer); ok {
					if strct, ok := ptr.Target.(*btf.Struct); ok {
						if strct.Name == filterStruct && i <= 5 {
							name := fnName
							if kprobeMulti && it.kmod != "" {
								name = fmt.Sprintf("%s [%s]", fnName, it.kmod)
							}
							funcs[name] = i
							continue
						}
					}
				}
				i += 1
			}
		}
	}

	return funcs, nil
}
