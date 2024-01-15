package sniff

import (
	"bytes"
	"context"
	"io"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

type SniffData struct {
	metadata *adapter.InboundContext
	err      error
}

type ChanSafe[T any] struct {
	status   bool
	datachan chan T
}

func (d *ChanSafe[T]) Close() {
	if !d.status {
		return
	}
	d.status = false
	close(d.datachan)
}

func (d *ChanSafe[T]) Push(data T) {
	if !d.status {
		return
	}
	d.datachan <- data
}

func (d *ChanSafe[T]) Pull() (T, error) {
	if !d.status {
		var null T
		return null, E.New("chan is closed")
	}
	data := <-d.datachan
	return data, nil
}

func NewChanSafeSniffData(length int) *ChanSafe[SniffData] {
	return &ChanSafe[SniffData]{
		status:   true,
		datachan: make(chan SniffData, length),
	}
}

type (
	StreamSniffer = func(ctx context.Context, reader io.Reader, sniffdata *ChanSafe[SniffData])
	PacketSniffer = func(ctx context.Context, packet []byte, sniffdata *ChanSafe[SniffData])
)

func PeekStream(ctx context.Context, conn net.Conn, buffer *buf.Buffer, timeout time.Duration, sniffers ...StreamSniffer) (*adapter.InboundContext, error) {
	if timeout == 0 {
		timeout = C.ReadPayloadTimeout
	}
	deadline := time.Now().Add(timeout)
	var errors []error
	err := conn.SetReadDeadline(deadline)
	if err != nil {
		return nil, E.Cause(err, "set read deadline")
	}
	_, err = buffer.ReadOnceFrom(conn)
	err = E.Errors(err, conn.SetReadDeadline(time.Time{}))
	if err != nil {
		return nil, E.Cause(err, "read payload")
	}
	sniffdata := NewChanSafeSniffData(len(sniffers))
	defer sniffdata.Close()
	for _, sniffer := range sniffers {
		go sniffer(ctx, bytes.NewReader(buffer.Bytes()), sniffdata)
	}
	for i := 0; i < len(sniffers); i++ {
		data, err := sniffdata.Pull()
		if err != nil {
			break
		}
		if data.metadata != nil {
			sniffdata.Close()
			return data.metadata, nil
		}
		if data.err != nil {
			errors = append(errors, data.err)
		}
	}
	return nil, E.Errors(errors...)
}

func PeekPacket(ctx context.Context, packet []byte, sniffers ...PacketSniffer) (*adapter.InboundContext, error) {
	var errors []error
	sniffdata := NewChanSafeSniffData(len(sniffers))
	defer sniffdata.Close()
	for _, sniffer := range sniffers {
		go sniffer(ctx, packet, sniffdata)
	}
	for i := 0; i < len(sniffers); i++ {
		data, err := sniffdata.Pull()
		if err != nil {
			break
		}
		if data.metadata != nil {
			return data.metadata, nil
		}
		if data.err != nil {
			errors = append(errors, data.err)
		}
	}
	return nil, E.Errors(errors...)
}

func (d *SniffData) GetMetadata() adapter.InboundContext {
	return *d.metadata
}

func (d *SniffData) GetErr() error {
	return d.err
}
