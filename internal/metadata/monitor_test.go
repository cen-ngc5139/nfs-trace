package metadata

import (
	"reflect"
	"testing"
)

func TestParseMountInfo(t *testing.T) {
	type args struct {
		filePath string
	}
	tests := []struct {
		name    string
		args    args
		want    []MountInfo
		wantErr bool
	}{
		{
			name: "Parse mount info",
			args: args{
				filePath: "../../testdata/container-mount-info",
			},
			want:    []MountInfo{},
			wantErr: false,
		},
		{
			name: "Parse mount info with error",
			args: args{
				filePath: "../../testdata/host-mount-info",
			},
			want:    nil,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseMountInfo(tt.args.filePath)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseMountInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseMountInfo() got = %v, want %v", got, tt.want)
			}
		})
	}
}
