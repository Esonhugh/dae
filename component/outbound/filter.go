/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) since 2023, v2rayA Organization <team@v2raya.org>
 */

package outbound

import (
	"fmt"
	"github.com/v2rayA/dae/component/outbound/dialer"
	"github.com/v2rayA/dae/pkg/config_parser"
	"regexp"
	"strings"
)

const (
	FilterInput_Name = "name"
	FilterInput_Link = "link"
)

const (
	FilterKey_Name_Regex   = "regex"
	FilterKey_Name_Keyword = "keyword"
)

type DialerSet struct {
	Dialers []*dialer.Dialer
}

func NewDialerSetFromLinks(option *dialer.GlobalOption, nodes []string) *DialerSet {
	s := &DialerSet{Dialers: make([]*dialer.Dialer, 0, len(nodes))}
	for _, node := range nodes {
		d, err := dialer.NewFromLink(option, dialer.InstanceOption{Check: false}, node)
		if err != nil {
			option.Log.Infof("failed to parse node: %v: %v", node, err)
			continue
		}
		s.Dialers = append(s.Dialers, d)
	}
	return s
}

func hit(dialer *dialer.Dialer, filters []*config_parser.Function) (hit bool, err error) {
	// Example
	// filter: name(regex:'^.*hk.*$', keyword:'sg') && name(keyword:'disney')
	// filter: !name(regex: 'HK|TW|SG') && name(keyword: disney)

	// And
	for _, filter := range filters {
		var subFilterHit bool

		switch filter.Name {
		case FilterInput_Name:
			// Or
			for _, param := range filter.Params {
				switch param.Key {
				case FilterKey_Name_Regex:
					matched, _ := regexp.MatchString(param.Val, dialer.Name())
					//logrus.Warnln(param.Val, matched, dialer.Name())
					if matched {
						subFilterHit = true
						break
					}
				case FilterKey_Name_Keyword:
					if strings.Contains(dialer.Name(), param.Val) {
						subFilterHit = true
						break
					}
				case "":
					return false, fmt.Errorf(`key of "filter: %v()" cannot be empty`, filter.Name)
				default:
					return false, fmt.Errorf(`unsupported filter key "%v" in "filter: %v()"`, param.Key, filter.Name)
				}
			}
		default:
			return false, fmt.Errorf(`unsupported filter input type: "%v"`, filter.Name)
		}

		if subFilterHit == filter.Not {
			return false, nil
		}
	}
	return true, nil
}

func (s *DialerSet) Filter(filters []*config_parser.Function) (dialers []*dialer.Dialer, err error) {
	for _, d := range s.Dialers {
		hit, err := hit(d, filters)
		if err != nil {
			return nil, err
		}
		if hit {
			dialers = append(dialers, d)
		}
	}
	return dialers, nil
}
