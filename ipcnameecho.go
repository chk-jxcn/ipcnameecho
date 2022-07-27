package ipcnameecho

import (
	"log"
	"net"
	"strings"
	"fmt"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
	"github.com/coredns/coredns/request"
)

type ipcnameecho struct {
	Next   plugin.Handler
	Config *config
	Upstream Upstreamer
}

// Upstreamer looks up targets of CNAME templates
type Upstreamer interface {
	Lookup(ctx context.Context, state request.Request, name string, typ uint16) (*dns.Msg, error)
}

type result struct {
	ReqType string
	IP      net.IP
	CNAME   string
	Domain	string
}

// ServeDNS implements the middleware.Handler interface.
func (p ipcnameecho) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	var rcode int
	if p.echo(ctx, w, r, &rcode) {
		return rcode, nil
	}
	return plugin.NextOrFailure(p.Name(), p.Next, ctx, w, r)
}

// Name implements the Handler interface.
func (ipcnameecho) Name() string { return "ipcnameecho" }

func soa(name string) dns.RR {
	s := fmt.Sprintf("%s 60 IN SOA ns1.%s postmaster.%s 1524370381 14400 3600 604800 60", name, name, name)
	soa, _ := dns.NewRR(s)
	return soa
}

func (p *ipcnameecho) echo(ctx context.Context, w dns.ResponseWriter, r *dns.Msg, rcode *int) bool {
	if len(r.Question) <= 0 {
		return false
	}

	*rcode = dns.RcodeSuccess

	state := request.Request{W: w, Req: r}
	var rrs []dns.RR
	m := new(dns.Msg)

	for i := 0; i < len(r.Question); i++ {
		question := r.Question[i]
		if question.Qclass != dns.ClassINET {
			continue
		}

		// Only handle type A right now
		if question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA {
			res := p.parseSubdomain(&question)
			if res == nil || res.ReqType == "" {
				if p.Config.Debug {
					log.Printf("[ipcnameecho] Parsed IP of '%s' is nil\n", question.Name)
				}
				continue
			}
			if res.ReqType == "ip" {
				if question.Qtype == dns.TypeAAAA {
					*rcode = 0
					m.SetRcode(r, dns.RcodeNameError)
					m.Ns = []dns.RR{soa(res.Domain)}
					w.WriteMsg(m)
					return true
				}
				// not an ip4
				ip := res.IP
				if ip4 := ip.To4(); ip4 != nil {
					if p.Config.Debug {
						log.Printf("[ipcnameecho] Parsed IP of '%s' is an IPv4 address\n", question.Name)
					}
					rrs = append(rrs, &dns.A{
						Hdr: dns.RR_Header{
							Name:   question.Name,
							Rrtype: dns.TypeA,
							Class:  dns.ClassINET,
							Ttl:    p.Config.TTL,
						},
						A: ip,
					})
				} else {
					if p.Config.Debug {
						log.Printf("[ipcnameecho] Parsed IP of '%s' fail\n", question.Name)
					}
					continue
				}
			} else if res.ReqType == "cname" {
				res.CNAME = res.CNAME + "."
				// cname should not have same root of this domain
				log.Printf("append cname record, %s\n", res.CNAME)
				rrs = append(rrs, &dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   question.Name,
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
						Ttl:    p.Config.TTL,
					},
					Target: res.CNAME,
				})
				if p.Upstream != nil && (state.QType() == dns.TypeA || state.QType() == dns.TypeAAAA) {
					if up, err := p.Upstream.Lookup(ctx, state, res.CNAME, state.QType()); err == nil && up != nil {
						m.Truncated = up.Truncated
						rrs = append(rrs, up.Answer...)
					}
				}

			}
		}
	}

	if len(rrs) > 0 {
		if p.Config.Debug {
			log.Printf("[ipcnameecho] Answering with %d rrs\n", len(rrs))
		}
		m.SetReply(r)
		m.Authoritative = true
		m.Answer = rrs
		m.Rcode = dns.RcodeSuccess
		w.WriteMsg(m)
		return true
	}
	return false
}

func (p *ipcnameecho) parseSubdomain(question *dns.Question) *result {
	domain := strings.SplitN(strings.ToLower(question.Name), ".", 2)
	if len(domain) != 2 {
		log.Printf("split domain fail", question.Name)
		return nil
	}

	for _, d := range p.Config.Domains {
		if domain[1] == d {
			subdomain := string(domain[0])
			r := &result{}
			r.Domain = d
			switch {
			case strings.HasPrefix(subdomain, "ip-"):
				r.ReqType = "ip"
				ip := strings.TrimPrefix(subdomain, "ip-")
				ip = strings.ReplaceAll(ip, "-", ".")
				r.IP = net.ParseIP(ip)
				if r.IP == nil {
					log.Printf("Not a IP", question.Name)
					return nil
				}
				return r
			case strings.HasPrefix(subdomain, "cname-"):
				r.ReqType = "cname"
				cname := strings.TrimPrefix(subdomain, "cname-")
				// a stupid escape
				cname = strings.ReplaceAll(cname, "--", "_")
				cname = strings.ReplaceAll(cname, "-d", ".")
				cname = strings.ReplaceAll(cname, "_", "-")
				r.CNAME = cname
				return r
			default:
				log.Printf("Not a IP, Cname reuqest", question.Name)
				return nil
			}
		}
	}

	if p.Config.Debug {
		log.Printf("[ipcnameecho] Query ('%s') does not end with one of the domains (%s)\n", question.Name, strings.Join(p.Config.Domains, ", "))
	}
	return nil
}
