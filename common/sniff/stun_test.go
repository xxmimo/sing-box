package sniff_test

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"

	"github.com/stretchr/testify/require"
)

func TestSniffSTUN(t *testing.T) {
	t.Parallel()
	packet, err := hex.DecodeString("000100002112a44224b1a025d0c180c484341306")
	require.NoError(t, err)
	sniffdata := sniff.NewChanSafeSniffData(1)
	sniff.STUNMessage(context.Background(), packet, sniffdata)
	data, err := sniffdata.Pull()
	if err != nil {
		return
	}
	metadata := data.GetMetadata()
	require.NoError(t, data.GetErr())
	require.Equal(t, metadata.Protocol, C.ProtocolSTUN)
}

func FuzzSniffSTUN(f *testing.F) {
	f.Fuzz(func(t *testing.T, data []byte) {
		sniffdata := sniff.NewChanSafeSniffData(1)
		sniff.STUNMessage(context.Background(), data, sniffdata)
		sdata, err := sniffdata.Pull()
		if err != nil {
			return
		}
		if err := sdata.GetErr(); err == nil {
			t.Fail()
		}
	})
}
