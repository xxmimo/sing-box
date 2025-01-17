package adapter

import (
	"context"
	"net"

	N "github.com/sagernet/sing/common/network"
)

// Note: for proxy protocols, outbound creates early connections by default.

type Outbound interface {
	Type() string
	Tag() string
	Port() int
	Network() []string
	Dependencies() []string
	N.Dialer
	NewConnection(ctx context.Context, conn net.Conn, metadata InboundContext) error
	NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata InboundContext) error
	SetTag(tag string)
}

type OutboundUseIP interface {
	UseIP() bool
}

type OutboundRelay interface {
	SetRelay(detour N.Dialer) Outbound
}
