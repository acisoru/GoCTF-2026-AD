package main

import (
	"archive/tar"
	"bytes"
)

func makeTar(name string, data []byte) []byte {
	var buffer bytes.Buffer
	writer := tar.NewWriter(&buffer)
	_ = writer.WriteHeader(&tar.Header{
		Name: name,
		Mode: 0o644,
		Size: int64(len(data)),
	})
	_, _ = writer.Write(data)
	_ = writer.Close()
	return buffer.Bytes()
}
