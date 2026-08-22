package model

import (
	"fmt"
	"net"
	"strings"
)

func CIDR(s string) (*net.IPNet, error) {
	ip, n, err := net.ParseCIDR(s)
	if err != nil {
		return nil, err
	}
	n.IP = ip
	return n, nil
}
func CanonicalCIDR(s string) (string, error) {
	n, e := CIDR(s)
	if e != nil {
		return "", e
	}
	return n.String(), nil
}
func IPIn(c, ip string) bool {
	n, e := CIDR(c)
	if e != nil {
		return false
	}
	if strings.Contains(ip, "/") {
		query, err := CIDR(ip)
		return err == nil && (n.Contains(query.IP) || query.Contains(n.IP))
	}
	parsed := net.ParseIP(ip)
	return parsed != nil && n.Contains(parsed)
}
func AddressRelation(a, b string) string {
	na, ea := CIDR(a)
	nb, eb := CIDR(b)
	if ea != nil || eb != nil {
		return "disjoint"
	}
	if na.String() == nb.String() {
		return "equal"
	}
	if na.Contains(nb.IP) {
		return "contains"
	}
	if nb.Contains(na.IP) {
		return "contained"
	}
	return "disjoint"
}
func ProtocolOverlap(a, b string) bool { return a == Any || b == Any || a == b }
func PortOverlap(a, b Rule) bool       { return a.PortFrom <= b.PortTo && b.PortFrom <= a.PortTo }
func ConditionsOverlap(a, b Rule) bool {
	return AddressRelation(a.Src, b.Src) != "disjoint" && AddressRelation(a.Dst, b.Dst) != "disjoint" && ProtocolOverlap(a.Protocol, b.Protocol) && PortOverlap(a, b)
}
func ConditionRelation(a, b Rule) string {
	sr := AddressRelation(a.Src, b.Src)
	dr := AddressRelation(a.Dst, b.Dst)
	if sr == "equal" && dr == "equal" && a.Protocol == b.Protocol && a.PortFrom == b.PortFrom && a.PortTo == b.PortTo {
		return "equal"
	}
	if sr == "contains" && dr != "disjoint" || dr == "contains" && sr != "disjoint" {
		return "contains"
	}
	if ConditionsOverlap(a, b) {
		return "intersect"
	}
	return "disjoint"
}
func PortString(r Rule) string {
	if r.PortFrom == r.PortTo {
		return fmt.Sprint(r.PortFrom)
	}
	return fmt.Sprintf("%d-%d", r.PortFrom, r.PortTo)
}
