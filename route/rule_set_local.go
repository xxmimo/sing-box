package route

import (
	"context"
	"os"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
)

var _ adapter.RuleSet = (*LocalRuleSet)(nil)

type LocalRuleSet struct {
	rules     []adapter.HeadlessRule
	useIPRule bool
	metadata  adapter.RuleSetMetadata
}

func NewLocalRuleSet(router adapter.Router, options option.RuleSet) (*LocalRuleSet, error) {
	var plainRuleSet option.PlainRuleSet
	switch options.Format {
	case C.RuleSetFormatSource, "":
		content, err := os.ReadFile(options.LocalOptions.Path)
		if err != nil {
			return nil, err
		}
		compat, err := json.UnmarshalExtended[option.PlainRuleSetCompat](content)
		if err != nil {
			return nil, err
		}
		plainRuleSet = compat.Upgrade()
	case C.RuleSetFormatBinary:
		setFile, err := os.Open(options.LocalOptions.Path)
		if err != nil {
			return nil, err
		}
		plainRuleSet, err = srs.Read(setFile, false)
		if err != nil {
			return nil, err
		}
	default:
		return nil, E.New("unknown rule set format: ", options.Format)
	}
	useIPRule := false
	rules := make([]adapter.HeadlessRule, len(plainRuleSet.Rules))
	for i, ruleOptions := range plainRuleSet.Rules {
		rule, err := NewHeadlessRule(router, ruleOptions)
		if err != nil {
			return nil, E.Cause(err, "parse rule_set.rules.[", i, "]")
		}
		rules[i] = rule
	}
	var metadata adapter.RuleSetMetadata
	metadata.ContainsProcessRule = hasHeadlessRule(plainRuleSet.Rules, isProcessHeadlessRule)
	metadata.ContainsWIFIRule = hasHeadlessRule(plainRuleSet.Rules, isWIFIHeadlessRule)
	metadata.ContainsIPCIDRRule = hasHeadlessRule(plainRuleSet.Rules, isIPCIDRHeadlessRule)
	return &LocalRuleSet{rules, useIPRule, metadata}, nil
}

func (s *LocalRuleSet) Match(metadata *adapter.InboundContext) bool {
	for _, rule := range s.rules {
		if rule.Match(metadata) {
			return true
		}
	}
	return false
}

func (s *LocalRuleSet) ContainsDestinationIPCIDRRule() bool {
	return s.metadata.ContainsIPCIDRRule
}

func (s *LocalRuleSet) StartContext(ctx context.Context, startContext adapter.RuleSetStartContext) error {
	return nil
}

func (s *LocalRuleSet) PostStart() error {
	return nil
}

func (s *LocalRuleSet) Metadata() adapter.RuleSetMetadata {
	return s.metadata
}

func (s *LocalRuleSet) Close() error {
	return nil
}
