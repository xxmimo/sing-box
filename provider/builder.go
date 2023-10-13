package provider

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/rw"
	"github.com/sagernet/sing/service/filemanager"
)

func New(ctx context.Context, router adapter.Router, logger log.ContextLogger, options option.OutboundProvider) (adapter.OutboundProvider, error) {
	if options.Path == "" {
		return nil, E.New("provider path missing")
	}
	path, _ := C.FindPath(options.Path)
	if foundPath, loaded := C.FindPath(path); loaded {
		path = foundPath
	}
	if !rw.FileExists(path) {
		path = filemanager.BasePath(ctx, path)
	}
	if options.HealthcheckUrl == "" {
		options.HealthcheckUrl = "https://www.gstatic.com/generate_204"
	}
	switch options.Type {
	case C.TypeFileProvider:
		return NewFileProvider(ctx, router, logger, options, path)
	case C.TypeHTTPProvider:
		return NewHTTPProvider(ctx, router, logger, options, path)
	default:
		return nil, E.New("invalid provider type")
	}
}
