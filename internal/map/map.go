package _map

import "github.com/cilium/ebpf"

type MapHandler interface {
	GetKey(mapName string) (interface{}, error)
	GetValue(mapName string) (interface{}, error)
	Update(mapName string, key interface{}, value interface{}) error
	Delete(mapName string, key interface{}) error
}

type Map struct {
}

func (m Map) GetKey(mapName string) (interface{}, error) {
	//TODO implement me
	panic("implement me")
}

func (m Map) GetValue(mapName string) (interface{}, error) {
	//TODO implement me
	panic("implement me")
}

func (m Map) Update(mapName string, key interface{}, value interface{}) error {
	em, err := ebpf.LoadPinnedMap(mapName, nil)
	if err != nil {
		return err
	}

	defer em.Close()

	return err
}

func (m Map) Delete(mapName string, key interface{}) error {
	//TODO implement me
	panic("implement me")
}

func NewMap() MapHandler {
	return &Map{}
}
