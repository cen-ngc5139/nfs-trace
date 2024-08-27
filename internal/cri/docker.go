package cri

type Docker struct {
	ID string
}

func (m Docker) GetPid() (int, error) {
	//TODO implement me
	panic("implement me")
}

func NewDocker(id string) Handler {
	return &Docker{
		ID: id,
	}
}
