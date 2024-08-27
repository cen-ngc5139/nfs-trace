package cri

type Handler interface {
	GetPid() (int, error)
}
