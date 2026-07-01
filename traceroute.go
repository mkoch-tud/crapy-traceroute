// main.go
package main

import (
	"bufio"
	"context"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/oschwald/maxminddb-golang"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

const (
	defaultUDPPort = 33434
	tcpSourceBase  = 40000

	colHop        = 4
	colAddress    = 40
	colAS         = 8
	colASName     = 28
	colCountry    = 20
	colCity       = 24
	colRTT        = 12
	colReplyHL    = 18
	colQuotedHL   = 18
	defaultCityDB = "ipinfo_location.mmdb"
	defaultASNDB  = "ipinfo_asn.mmdb"
)

var rowFormat = fmt.Sprintf(
	"%%-%dd %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds\n",
	colHop,
	colAddress,
	colAS,
	colASName,
	colCountry,
	colCity,
	colRTT,
	colReplyHL,
	colQuotedHL,
)

var headerFormat = fmt.Sprintf(
	"%%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds %%-%ds\n",
	colHop,
	colAddress,
	colAS,
	colASName,
	colCountry,
	colCity,
	colRTT,
	colReplyHL,
	colQuotedHL,
)

type Hop struct {
	Target string
	TTL    int

	Addr     string
	RTT      time.Duration
	Done     bool
	TimedOut bool
	Late     bool

	ReturnedHopLimit    int
	HasReturnedHopLimit bool

	QuotedHopLimit    int
	HasQuotedHopLimit bool

	AS      string
	ASName  string
	Country string
	City    string
}

type rawHop struct {
	Target string
	TTL    int

	Addr     string
	RTT      time.Duration
	Done     bool
	TimedOut bool

	ReturnedHopLimit    int
	HasReturnedHopLimit bool

	QuotedHopLimit    int
	HasQuotedHopLimit bool
}

type Target struct {
	Input string
	IP    net.IP
	IPv6  bool
	Index int
}

type TraceMode string

const (
	traceModeICMP TraceMode = "icmp"
	traceModeUDP  TraceMode = "udp"
	traceModeTCP  TraceMode = "tcp"
)

type TraceOptions struct {
	Interface string
	SourceIP  net.IP
	Mode      TraceMode
	Port      int
}

type GeoLookup struct {
	cityDB *maxminddb.Reader
	asnDB  *maxminddb.Reader
}

type CSVOutput struct {
	writer *csv.Writer
	file   *os.File
	mu     sync.Mutex
}

func main() {
	var (
		maxHops             = flag.Int("m", 30, "maximum hops")
		timeout             = flag.Duration("w", 2*time.Second, "per-hop timeout")
		reorderWindow       = flag.Duration("reorder", 500*time.Millisecond, "out-of-order print reorder window")
		sendInterval        = flag.Duration("send-interval", 500*time.Millisecond, "delay between sending probes")
		mode                = flag.String("mode", "icmp", "traceroute probe mode: icmp, udp, or tcp")
		port                = flag.Int("port", 0, "destination port for tcp mode; optional base destination port for udp mode")
		iface               = flag.String("iface", "", "network interface to send probes on")
		src                 = flag.String("src", "", "source IP address to bind probe sockets to")
		inputFile           = flag.String("input-file", "", "file containing one literal IPv4/IPv6 address per line")
		csvMode             = flag.Bool("csv", false, "also write traceroute results to CSV")
		outputFile          = flag.String("output-file", "", "CSV output file path")
		identifyTTLRewrites = flag.Bool("identify-ttl-rewrites", false, "CSV mode: only save the hop before the final observed hop when final quoted_ttl/hlim > 1")
		cityMMDB            = flag.String("geo-city-mmdb", "", "path to city/country MMDB file")
		asnMMDB             = flag.String("geo-asn-mmdb", "", "path to ASN MMDB file")
	)
	flag.Parse()

	targetInputs, err := collectTargetInputs(flag.Args(), *inputFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "input:", err)
		os.Exit(1)
	}

	if len(targetInputs) == 0 {
		fmt.Fprintf(
			os.Stderr,
			"usage: %s [flags] ip-address [ip-address ...]\n\nflags:\n",
			os.Args[0],
		)
		flag.PrintDefaults()
		os.Exit(2)
	}

	if *identifyTTLRewrites {
		*csvMode = true
	}

	if *csvMode && *outputFile == "" {
		fmt.Fprintln(os.Stderr, "csv: -output-file is required when -csv or -identify-ttl-rewrites is used")
		os.Exit(2)
	}

	targets, err := parseTargets(targetInputs)
	if err != nil {
		fmt.Fprintln(os.Stderr, "input:", err)
		os.Exit(1)
	}

	traceOpts, err := parseTraceOptions(*iface, *src, *mode, *port)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trace options:", err)
		os.Exit(2)
	}

	*cityMMDB = autoMMDBPath(*cityMMDB, defaultCityDB, "city/location")
	*asnMMDB = autoMMDBPath(*asnMMDB, defaultASNDB, "ASN")

	geo, err := openGeoLookup(*cityMMDB, *asnMMDB)
	if err != nil {
		fmt.Fprintln(os.Stderr, "geo:", err)
		os.Exit(1)
	}
	defer geo.Close()

	var csvOut *CSVOutput
	if *csvMode {
		csvOut, err = openCSVOutput(*outputFile, *identifyTTLRewrites)
		if err != nil {
			fmt.Fprintln(os.Stderr, "csv:", err)
			os.Exit(1)
		}
		defer csvOut.Close()
	}

	for i, target := range targets {
		if i > 0 {
			fmt.Println()
		}

		fmt.Printf("traceroute to %s, %d hops max, %s mode\n", target.IP, *maxHops, traceOpts.Mode)
		printHeader()

		hops, err := runTraceroute(target, *maxHops, *timeout, *sendInterval, *reorderWindow, traceOpts, geo)
		if err != nil {
			fmt.Fprintf(os.Stderr, "trace %s: %v\n", target.Input, err)
			continue
		}

		if csvOut != nil {
			if *identifyTTLRewrites {
				if err := csvOut.WriteIdentifyRows(target.Input, hops); err != nil {
					fmt.Fprintln(os.Stderr, "csv:", err)
				}
			} else {
				if err := csvOut.WriteHopRows(target.Input, hops); err != nil {
					fmt.Fprintln(os.Stderr, "csv:", err)
				}
			}
		}
	}
}

func collectTargetInputs(args []string, inputFile string) ([]string, error) {
	var inputs []string

	for _, arg := range args {
		arg = strings.TrimSpace(arg)
		if arg != "" {
			inputs = append(inputs, arg)
		}
	}

	if inputFile == "" {
		return inputs, nil
	}

	f, err := os.Open(inputFile)
	if err != nil {
		return nil, fmt.Errorf("open input file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		if len(fields) > 1 {
			return nil, fmt.Errorf("%s:%d contains more than one field; expected one IP address per line", inputFile, lineNo)
		}

		inputs = append(inputs, fields[0])
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read input file: %w", err)
	}

	return inputs, nil
}

func parseTargets(inputs []string) ([]Target, error) {
	targets := make([]Target, 0, len(inputs))

	for i, input := range inputs {
		ip, isIPv6, err := parseLiteralIP(input)
		if err != nil {
			return nil, err
		}

		targets = append(targets, Target{
			Input: input,
			IP:    ip,
			IPv6:  isIPv6,
			Index: i,
		})
	}

	return targets, nil
}

func parseTraceOptions(iface string, src string, mode string, port int) (TraceOptions, error) {
	opts := TraceOptions{
		Interface: strings.TrimSpace(iface),
		Mode:      TraceMode(strings.ToLower(strings.TrimSpace(mode))),
	}
	if opts.Mode == "" {
		opts.Mode = traceModeICMP
	}

	switch opts.Mode {
	case traceModeICMP:
		if port != 0 {
			return TraceOptions{}, fmt.Errorf("-port is only valid with -mode udp or -mode tcp")
		}
	case traceModeUDP:
		if port == 0 {
			port = defaultUDPPort
		}
		if port < 1 || port > 65535 {
			return TraceOptions{}, fmt.Errorf("-port must be between 1 and 65535")
		}
	case traceModeTCP:
		if port == 0 {
			return TraceOptions{}, fmt.Errorf("-port is required with -mode tcp")
		}
		if port < 1 || port > 65535 {
			return TraceOptions{}, fmt.Errorf("-port must be between 1 and 65535")
		}
	default:
		return TraceOptions{}, fmt.Errorf("unsupported -mode %q; use icmp, udp, or tcp", mode)
	}
	opts.Port = port

	src = strings.TrimSpace(src)
	if src == "" {
		return opts, nil
	}

	ip, _, err := parseLiteralIP(src)
	if err != nil {
		return TraceOptions{}, fmt.Errorf("invalid -src: %w", err)
	}

	opts.SourceIP = ip
	return opts, nil
}

func listenAddress(opts TraceOptions, ipv6Target bool) (string, error) {
	if opts.SourceIP == nil {
		if ipv6Target {
			return "::", nil
		}
		return "0.0.0.0", nil
	}

	if ipv6Target {
		if opts.SourceIP.To4() != nil {
			return "", fmt.Errorf("-src %s is IPv4 but target is IPv6", opts.SourceIP)
		}

		address := opts.SourceIP.String()
		if opts.Interface != "" {
			address += "%" + opts.Interface
		}
		return address, nil
	}

	v4 := opts.SourceIP.To4()
	if v4 == nil {
		return "", fmt.Errorf("-src %s is IPv6 but target is IPv4", opts.SourceIP)
	}

	return v4.String(), nil
}

func listenTracePacket(network string, address string, iface string) (net.PacketConn, error) {
	lc := net.ListenConfig{}
	if iface != "" {
		lc.Control = func(network string, address string, c syscall.RawConn) error {
			var sockErr error
			if err := c.Control(func(fd uintptr) {
				sockErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
			}); err != nil {
				return err
			}
			if sockErr != nil {
				return fmt.Errorf("bind socket to interface %q: %w", iface, sockErr)
			}
			return nil
		}
	}

	c, err := lc.ListenPacket(context.Background(), network, address)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func runTraceroute(target Target, maxHops int, timeout time.Duration, sendInterval time.Duration, reorderWindow time.Duration, opts TraceOptions, geo *GeoLookup) ([]Hop, error) {
	rawCh := make(chan rawHop, maxHops*4)
	enrichedCh := make(chan Hop, maxHops*4)

	var geoWG sync.WaitGroup

	go enrichLoop(rawCh, enrichedCh, &geoWG, geo)

	printDone := make(chan []Hop, 1)

	go func() {
		printDone <- printOrdered(enrichedCh, maxHops, reorderWindow)
	}()

	var err error
	switch opts.Mode {
	case traceModeICMP:
		if target.IPv6 {
			err = traceICMP6(target, maxHops, timeout, sendInterval, opts, rawCh)
		} else {
			err = traceICMP4(target, maxHops, timeout, sendInterval, opts, rawCh)
		}
	case traceModeUDP:
		if target.IPv6 {
			err = traceUDP6(target, maxHops, timeout, sendInterval, opts, rawCh)
		} else {
			err = traceUDP4(target, maxHops, timeout, sendInterval, opts, rawCh)
		}
	case traceModeTCP:
		if target.IPv6 {
			err = traceTCP6(target, maxHops, timeout, sendInterval, opts, rawCh)
		} else {
			err = traceTCP4(target, maxHops, timeout, sendInterval, opts, rawCh)
		}
	}

	close(rawCh)
	geoWG.Wait()
	close(enrichedCh)

	hops := <-printDone

	return hops, err
}

func printHeader() {
	fmt.Printf(
		headerFormat,
		"hop",
		"address",
		"AS",
		"AS name",
		"country",
		"city",
		"rtt",
		"reply_ttl/hlim",
		"quoted_ttl/hlim",
	)
}

func autoMMDBPath(flagValue, defaultPath, label string) string {
	if flagValue != "" {
		return flagValue
	}

	if _, err := os.Stat(defaultPath); err == nil {
		fmt.Printf("geo: no %s MMDB flag provided, using ./%s\n", label, defaultPath)
		return defaultPath
	}

	fmt.Printf("geo: no %s MMDB flag provided and ./%s not found, skipping %s lookup\n", label, defaultPath, label)
	return ""
}

func parseLiteralIP(input string) (net.IP, bool, error) {
	ip := net.ParseIP(input)
	if ip == nil {
		return nil, false, fmt.Errorf("invalid IP address %q; only literal IPv4 or IPv6 addresses are allowed", input)
	}

	if v4 := ip.To4(); v4 != nil {
		return v4, false, nil
	}

	if ip.To16() != nil {
		return ip, true, nil
	}

	return nil, false, fmt.Errorf("invalid IP address %q", input)
}

func traceICMP4(target Target, maxHops int, timeout time.Duration, sendInterval time.Duration, opts TraceOptions, out chan<- rawHop) error {
	address, err := listenAddress(opts, false)
	if err != nil {
		return err
	}

	c, err := listenTracePacket("ip4:icmp", address, opts.Interface)
	if err != nil {
		return err
	}
	defer c.Close()

	pc := ipv4.NewPacketConn(c)

	if err := pc.SetControlMessage(ipv4.FlagTTL, true); err != nil {
		return fmt.Errorf("enable IPv4 TTL control message: %w", err)
	}

	id := (os.Getpid() + target.Index) & 0xffff
	startTimes := make(map[int]time.Time, maxHops)

	var mu sync.Mutex
	seen := make(map[int]bool, maxHops)

	done := make(chan struct{})

	var closeDoneOnce sync.Once
	closeDone := func() {
		closeDoneOnce.Do(func() {
			close(done)
		})
	}

	var wg sync.WaitGroup

	defer func() {
		closeDone()
		wg.Wait()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		buf := make([]byte, 1500)

		for {
			select {
			case <-done:
				return
			default:
			}

			_ = pc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

			n, cm, peer, err := pc.ReadFrom(buf)
			if err != nil {
				continue
			}

			returnedTTL := 0
			hasReturnedTTL := false
			if cm != nil && cm.TTL > 0 {
				returnedTTL = cm.TTL
				hasReturnedTTL = true
			}

			rm, err := icmp.ParseMessage(1, buf[:n])
			if err != nil {
				continue
			}

			var (
				ttl       int
				ok        bool
				isDone    bool
				quotedTTL int
				hasQuoted bool
			)

			switch rm.Type {
			case ipv4.ICMPTypeEchoReply:
				echo, good := rm.Body.(*icmp.Echo)
				if !good || echo.ID != id {
					continue
				}

				ttl = echo.Seq
				ok = true
				isDone = true

			case ipv4.ICMPTypeTimeExceeded:
				ttl, quotedTTL, ok = matchEmbeddedEcho4(rm.Body, id)
				hasQuoted = ok

			case ipv4.ICMPTypeDestinationUnreachable:
				ttl, quotedTTL, ok = matchEmbeddedEcho4(rm.Body, id)
				hasQuoted = ok
				isDone = ok
			}

			if !ok || ttl < 1 || ttl > maxHops {
				continue
			}

			mu.Lock()
			if seen[ttl] {
				mu.Unlock()
				continue
			}

			seen[ttl] = true
			start := startTimes[ttl]
			mu.Unlock()

			if start.IsZero() {
				continue
			}

			out <- rawHop{
				Target:              target.Input,
				TTL:                 ttl,
				Addr:                peer.String(),
				RTT:                 time.Since(start),
				Done:                isDone,
				ReturnedHopLimit:    returnedTTL,
				HasReturnedHopLimit: hasReturnedTTL,
				QuotedHopLimit:      quotedTTL,
				HasQuotedHopLimit:   hasQuoted,
			}

			if isDone {
				closeDone()
				return
			}
		}
	}()

	for ttl := 1; ttl <= maxHops; ttl++ {
		select {
		case <-done:
			return nil
		default:
		}

		if err := pc.SetTTL(ttl); err != nil {
			return err
		}

		msg := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{
				ID:   id,
				Seq:  ttl,
				Data: []byte("go-traceroute-v4"),
			},
		}

		b, err := msg.Marshal(nil)
		if err != nil {
			return err
		}

		mu.Lock()
		startTimes[ttl] = time.Now()
		mu.Unlock()

		if _, err := c.WriteTo(b, &net.IPAddr{IP: target.IP}); err != nil {
			return err
		}

		wg.Add(1)
		go func(ttl int) {
			defer wg.Done()

			timer := time.NewTimer(timeout)
			defer timer.Stop()

			select {
			case <-timer.C:
				mu.Lock()
				if seen[ttl] {
					mu.Unlock()
					return
				}

				seen[ttl] = true
				mu.Unlock()

				out <- rawHop{
					Target:   target.Input,
					TTL:      ttl,
					TimedOut: true,
				}

			case <-done:
				return
			}
		}(ttl)

		select {
		case <-done:
			return nil
		case <-time.After(sendInterval):
		}
	}

	finalTimer := time.NewTimer(timeout)
	defer finalTimer.Stop()

	select {
	case <-finalTimer.C:
	case <-done:
	}

	return nil
}

func matchEmbeddedEcho4(body icmp.MessageBody, id int) (ttl int, quotedTTL int, ok bool) {
	var data []byte

	switch b := body.(type) {
	case *icmp.TimeExceeded:
		data = b.Data
	case *icmp.DstUnreach:
		data = b.Data
	default:
		return 0, 0, false
	}

	h, err := icmp.ParseIPv4Header(data)
	if err != nil || len(data) < h.Len {
		return 0, 0, false
	}

	embedded, err := icmp.ParseMessage(1, data[h.Len:])
	if err != nil {
		return 0, 0, false
	}

	echo, good := embedded.Body.(*icmp.Echo)
	if !good || echo.ID != id {
		return 0, 0, false
	}

	return echo.Seq, h.TTL, true
}

func traceICMP6(target Target, maxHops int, timeout time.Duration, sendInterval time.Duration, opts TraceOptions, out chan<- rawHop) error {
	address, err := listenAddress(opts, true)
	if err != nil {
		return err
	}

	c, err := listenTracePacket("ip6:ipv6-icmp", address, opts.Interface)
	if err != nil {
		return err
	}
	defer c.Close()

	pc := ipv6.NewPacketConn(c)

	if err := pc.SetControlMessage(ipv6.FlagHopLimit, true); err != nil {
		return fmt.Errorf("enable IPv6 HopLimit control message: %w", err)
	}

	id := (os.Getpid() + target.Index) & 0xffff
	startTimes := make(map[int]time.Time, maxHops)

	var mu sync.Mutex
	seen := make(map[int]bool, maxHops)

	done := make(chan struct{})

	var closeDoneOnce sync.Once
	closeDone := func() {
		closeDoneOnce.Do(func() {
			close(done)
		})
	}

	var wg sync.WaitGroup

	defer func() {
		closeDone()
		wg.Wait()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		buf := make([]byte, 1500)

		for {
			select {
			case <-done:
				return
			default:
			}

			_ = pc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

			n, cm, peer, err := pc.ReadFrom(buf)
			if err != nil {
				continue
			}

			returnedHopLimit := 0
			hasReturnedHopLimit := false
			if cm != nil && cm.HopLimit > 0 {
				returnedHopLimit = cm.HopLimit
				hasReturnedHopLimit = true
			}

			rm, err := icmp.ParseMessage(58, buf[:n])
			if err != nil {
				continue
			}

			var (
				ttl            int
				ok             bool
				isDone         bool
				quotedHopLimit int
				hasQuoted      bool
			)

			switch rm.Type {
			case ipv6.ICMPTypeEchoReply:
				echo, good := rm.Body.(*icmp.Echo)
				if !good || echo.ID != id {
					continue
				}

				ttl = echo.Seq
				ok = true
				isDone = true

			case ipv6.ICMPTypeTimeExceeded:
				ttl, quotedHopLimit, ok = matchEmbeddedEcho6(rm.Body, id)
				hasQuoted = ok

			case ipv6.ICMPTypeDestinationUnreachable:
				ttl, quotedHopLimit, ok = matchEmbeddedEcho6(rm.Body, id)
				hasQuoted = ok
				isDone = ok
			}

			if !ok || ttl < 1 || ttl > maxHops {
				continue
			}

			mu.Lock()
			if seen[ttl] {
				mu.Unlock()
				continue
			}

			seen[ttl] = true
			start := startTimes[ttl]
			mu.Unlock()

			if start.IsZero() {
				continue
			}

			out <- rawHop{
				Target:              target.Input,
				TTL:                 ttl,
				Addr:                peer.String(),
				RTT:                 time.Since(start),
				Done:                isDone,
				ReturnedHopLimit:    returnedHopLimit,
				HasReturnedHopLimit: hasReturnedHopLimit,
				QuotedHopLimit:      quotedHopLimit,
				HasQuotedHopLimit:   hasQuoted,
			}

			if isDone {
				closeDone()
				return
			}
		}
	}()

	for hopLimit := 1; hopLimit <= maxHops; hopLimit++ {
		select {
		case <-done:
			return nil
		default:
		}

		if err := pc.SetHopLimit(hopLimit); err != nil {
			return err
		}

		msg := icmp.Message{
			Type: ipv6.ICMPTypeEchoRequest,
			Code: 0,
			Body: &icmp.Echo{
				ID:   id,
				Seq:  hopLimit,
				Data: []byte("go-traceroute-v6"),
			},
		}

		b, err := msg.Marshal(nil)
		if err != nil {
			return err
		}

		mu.Lock()
		startTimes[hopLimit] = time.Now()
		mu.Unlock()

		if _, err := c.WriteTo(b, &net.IPAddr{IP: target.IP}); err != nil {
			return err
		}

		wg.Add(1)
		go func(ttl int) {
			defer wg.Done()

			timer := time.NewTimer(timeout)
			defer timer.Stop()

			select {
			case <-timer.C:
				mu.Lock()
				if seen[ttl] {
					mu.Unlock()
					return
				}

				seen[ttl] = true
				mu.Unlock()

				out <- rawHop{
					Target:   target.Input,
					TTL:      ttl,
					TimedOut: true,
				}

			case <-done:
				return
			}
		}(hopLimit)

		select {
		case <-done:
			return nil
		case <-time.After(sendInterval):
		}
	}

	finalTimer := time.NewTimer(timeout)
	defer finalTimer.Stop()

	select {
	case <-finalTimer.C:
	case <-done:
	}

	return nil
}

func matchEmbeddedEcho6(body icmp.MessageBody, id int) (ttl int, quotedHopLimit int, ok bool) {
	var data []byte

	switch b := body.(type) {
	case *icmp.TimeExceeded:
		data = b.Data
	case *icmp.DstUnreach:
		data = b.Data
	default:
		return 0, 0, false
	}

	if len(data) < ipv6.HeaderLen {
		return 0, 0, false
	}

	h, err := ipv6.ParseHeader(data)
	if err != nil {
		return 0, 0, false
	}

	embedded, err := icmp.ParseMessage(58, data[ipv6.HeaderLen:])
	if err != nil {
		return 0, 0, false
	}

	echo, good := embedded.Body.(*icmp.Echo)
	if !good || echo.ID != id {
		return 0, 0, false
	}

	return echo.Seq, h.HopLimit, true
}

func traceUDP4(target Target, maxHops int, timeout time.Duration, sendInterval time.Duration, opts TraceOptions, out chan<- rawHop) error {
	if err := validateSourceFamily(opts, false); err != nil {
		return err
	}
	if opts.Port+maxHops-1 > 65535 {
		return fmt.Errorf("udp base -port %d is too high for %d hops", opts.Port, maxHops)
	}

	icmpConn, err := listenTracePacket("ip4:icmp", listenAnyAddress(opts, false), opts.Interface)
	if err != nil {
		return err
	}
	defer icmpConn.Close()
	icmpPC := ipv4.NewPacketConn(icmpConn)
	if err := icmpPC.SetControlMessage(ipv4.FlagTTL, true); err != nil {
		return fmt.Errorf("enable IPv4 TTL control message: %w", err)
	}

	udpConn, err := listenTracePacket("udp4", udpListenAddress(opts, false), opts.Interface)
	if err != nil {
		return err
	}
	defer udpConn.Close()
	udpPC := ipv4.NewPacketConn(udpConn)

	startTimes := make(map[int]time.Time, maxHops)
	var mu sync.Mutex
	seen := make(map[int]bool, maxHops)
	done := make(chan struct{})
	var closeDoneOnce sync.Once
	closeDone := func() { closeDoneOnce.Do(func() { close(done) }) }
	var wg sync.WaitGroup
	defer func() { closeDone(); wg.Wait() }()

	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 1500)
		for {
			select {
			case <-done:
				return
			default:
			}
			_ = icmpPC.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, cm, peer, err := icmpPC.ReadFrom(buf)
			if err != nil {
				continue
			}
			returnedTTL, hasReturnedTTL := 0, false
			if cm != nil && cm.TTL > 0 {
				returnedTTL, hasReturnedTTL = cm.TTL, true
			}
			rm, err := icmp.ParseMessage(1, buf[:n])
			if err != nil {
				continue
			}
			var ttl, quotedTTL int
			var ok, isDone bool
			switch rm.Type {
			case ipv4.ICMPTypeTimeExceeded:
				ttl, quotedTTL, ok = matchEmbeddedUDP4(rm.Body, opts.Port)
			case ipv4.ICMPTypeDestinationUnreachable:
				ttl, quotedTTL, ok = matchEmbeddedUDP4(rm.Body, opts.Port)
				isDone = ok
			}
			if !ok || ttl < 1 || ttl > maxHops {
				continue
			}
			mu.Lock()
			if seen[ttl] {
				mu.Unlock()
				continue
			}
			seen[ttl] = true
			start := startTimes[ttl]
			mu.Unlock()
			if start.IsZero() {
				continue
			}
			out <- rawHop{Target: target.Input, TTL: ttl, Addr: peer.String(), RTT: time.Since(start), Done: isDone, ReturnedHopLimit: returnedTTL, HasReturnedHopLimit: hasReturnedTTL, QuotedHopLimit: quotedTTL, HasQuotedHopLimit: true}
			if isDone {
				closeDone()
				return
			}
		}
	}()

	for ttl := 1; ttl <= maxHops; ttl++ {
		select {
		case <-done:
			return nil
		default:
		}
		if err := udpPC.SetTTL(ttl); err != nil {
			return err
		}
		mu.Lock()
		startTimes[ttl] = time.Now()
		mu.Unlock()
		port := opts.Port + ttl - 1
		if _, err := udpConn.WriteTo([]byte("go-traceroute-udp4"), &net.UDPAddr{IP: target.IP, Port: port}); err != nil {
			return err
		}
		startTimeout(&wg, &mu, seen, done, out, target.Input, ttl, timeout)
		select {
		case <-done:
			return nil
		case <-time.After(sendInterval):
		}
	}
	waitForDone(done, timeout)
	return nil
}

func traceUDP6(target Target, maxHops int, timeout time.Duration, sendInterval time.Duration, opts TraceOptions, out chan<- rawHop) error {
	if err := validateSourceFamily(opts, true); err != nil {
		return err
	}
	if opts.Port+maxHops-1 > 65535 {
		return fmt.Errorf("udp base -port %d is too high for %d hops", opts.Port, maxHops)
	}

	icmpConn, err := listenTracePacket("ip6:ipv6-icmp", listenAnyAddress(opts, true), opts.Interface)
	if err != nil {
		return err
	}
	defer icmpConn.Close()
	icmpPC := ipv6.NewPacketConn(icmpConn)
	if err := icmpPC.SetControlMessage(ipv6.FlagHopLimit, true); err != nil {
		return fmt.Errorf("enable IPv6 HopLimit control message: %w", err)
	}

	udpConn, err := listenTracePacket("udp6", udpListenAddress(opts, true), opts.Interface)
	if err != nil {
		return err
	}
	defer udpConn.Close()
	udpPC := ipv6.NewPacketConn(udpConn)

	startTimes := make(map[int]time.Time, maxHops)
	var mu sync.Mutex
	seen := make(map[int]bool, maxHops)
	done := make(chan struct{})
	var closeDoneOnce sync.Once
	closeDone := func() { closeDoneOnce.Do(func() { close(done) }) }
	var wg sync.WaitGroup
	defer func() { closeDone(); wg.Wait() }()

	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 1500)
		for {
			select {
			case <-done:
				return
			default:
			}
			_ = icmpPC.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, cm, peer, err := icmpPC.ReadFrom(buf)
			if err != nil {
				continue
			}
			returnedHopLimit, hasReturnedHopLimit := 0, false
			if cm != nil && cm.HopLimit > 0 {
				returnedHopLimit, hasReturnedHopLimit = cm.HopLimit, true
			}
			rm, err := icmp.ParseMessage(58, buf[:n])
			if err != nil {
				continue
			}
			var ttl, quotedHopLimit int
			var ok, isDone bool
			switch rm.Type {
			case ipv6.ICMPTypeTimeExceeded:
				ttl, quotedHopLimit, ok = matchEmbeddedUDP6(rm.Body, opts.Port)
			case ipv6.ICMPTypeDestinationUnreachable:
				ttl, quotedHopLimit, ok = matchEmbeddedUDP6(rm.Body, opts.Port)
				isDone = ok
			}
			if !ok || ttl < 1 || ttl > maxHops {
				continue
			}
			mu.Lock()
			if seen[ttl] {
				mu.Unlock()
				continue
			}
			seen[ttl] = true
			start := startTimes[ttl]
			mu.Unlock()
			if start.IsZero() {
				continue
			}
			out <- rawHop{Target: target.Input, TTL: ttl, Addr: peer.String(), RTT: time.Since(start), Done: isDone, ReturnedHopLimit: returnedHopLimit, HasReturnedHopLimit: hasReturnedHopLimit, QuotedHopLimit: quotedHopLimit, HasQuotedHopLimit: true}
			if isDone {
				closeDone()
				return
			}
		}
	}()

	for hopLimit := 1; hopLimit <= maxHops; hopLimit++ {
		select {
		case <-done:
			return nil
		default:
		}
		if err := udpPC.SetHopLimit(hopLimit); err != nil {
			return err
		}
		mu.Lock()
		startTimes[hopLimit] = time.Now()
		mu.Unlock()
		port := opts.Port + hopLimit - 1
		if _, err := udpConn.WriteTo([]byte("go-traceroute-udp6"), &net.UDPAddr{IP: target.IP, Port: port}); err != nil {
			return err
		}
		startTimeout(&wg, &mu, seen, done, out, target.Input, hopLimit, timeout)
		select {
		case <-done:
			return nil
		case <-time.After(sendInterval):
		}
	}
	waitForDone(done, timeout)
	return nil
}

func traceTCP4(target Target, maxHops int, timeout time.Duration, sendInterval time.Duration, opts TraceOptions, out chan<- rawHop) error {
	return traceTCP(target, maxHops, timeout, sendInterval, opts, out, false)
}

func traceTCP6(target Target, maxHops int, timeout time.Duration, sendInterval time.Duration, opts TraceOptions, out chan<- rawHop) error {
	return traceTCP(target, maxHops, timeout, sendInterval, opts, out, true)
}

func traceTCP(target Target, maxHops int, timeout time.Duration, sendInterval time.Duration, opts TraceOptions, out chan<- rawHop, ipv6Target bool) error {
	if err := validateSourceFamily(opts, ipv6Target); err != nil {
		return err
	}
	if tcpSourceBase+target.Index*maxHops+maxHops > 65535 {
		return fmt.Errorf("too many targets/hops for tcp source-port encoding")
	}

	network := "ip4:icmp"
	if ipv6Target {
		network = "ip6:ipv6-icmp"
	}
	icmpConn, err := listenTracePacket(network, listenAnyAddress(opts, ipv6Target), opts.Interface)
	if err != nil {
		return err
	}
	defer icmpConn.Close()

	startTimes := make(map[int]time.Time, maxHops)
	var mu sync.Mutex
	seen := make(map[int]bool, maxHops)
	done := make(chan struct{})
	var closeDoneOnce sync.Once
	closeDone := func() { closeDoneOnce.Do(func() { close(done) }) }
	var wg sync.WaitGroup
	defer func() { closeDone(); wg.Wait() }()

	if ipv6Target {
		pc := ipv6.NewPacketConn(icmpConn)
		if err := pc.SetControlMessage(ipv6.FlagHopLimit, true); err != nil {
			return fmt.Errorf("enable IPv6 HopLimit control message: %w", err)
		}
		wg.Add(1)
		go readTCPICMP6(pc, target, maxHops, opts, startTimes, &mu, seen, done, closeDone, out, &wg)
	} else {
		pc := ipv4.NewPacketConn(icmpConn)
		if err := pc.SetControlMessage(ipv4.FlagTTL, true); err != nil {
			return fmt.Errorf("enable IPv4 TTL control message: %w", err)
		}
		wg.Add(1)
		go readTCPICMP4(pc, target, maxHops, opts, startTimes, &mu, seen, done, closeDone, out, &wg)
	}

	for ttl := 1; ttl <= maxHops; ttl++ {
		select {
		case <-done:
			return nil
		default:
		}
		mu.Lock()
		startTimes[ttl] = time.Now()
		mu.Unlock()
		sourcePort := tcpSourcePort(target.Index, maxHops, ttl)
		wg.Add(1)
		go dialTCPProbe(&wg, &mu, seen, done, closeDone, out, target, ttl, sourcePort, timeout, opts, ipv6Target)
		startTimeout(&wg, &mu, seen, done, out, target.Input, ttl, timeout)
		select {
		case <-done:
			return nil
		case <-time.After(sendInterval):
		}
	}
	waitForDone(done, timeout)
	return nil
}

func readTCPICMP4(pc *ipv4.PacketConn, target Target, maxHops int, opts TraceOptions, startTimes map[int]time.Time, mu *sync.Mutex, seen map[int]bool, done <-chan struct{}, closeDone func(), out chan<- rawHop, wg *sync.WaitGroup) {
	defer wg.Done()
	buf := make([]byte, 1500)
	for {
		select {
		case <-done:
			return
		default:
		}
		_ = pc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, cm, peer, err := pc.ReadFrom(buf)
		if err != nil {
			continue
		}
		returnedTTL, hasReturnedTTL := 0, false
		if cm != nil && cm.TTL > 0 {
			returnedTTL, hasReturnedTTL = cm.TTL, true
		}
		rm, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			continue
		}
		var ttl, quotedTTL int
		var ok, isDone bool
		switch rm.Type {
		case ipv4.ICMPTypeTimeExceeded:
			ttl, quotedTTL, ok = matchEmbeddedTCP4(rm.Body, target.Index, maxHops)
		case ipv4.ICMPTypeDestinationUnreachable:
			ttl, quotedTTL, ok = matchEmbeddedTCP4(rm.Body, target.Index, maxHops)
			isDone = ok
		}
		if !ok || ttl < 1 || ttl > maxHops {
			continue
		}
		emitSeenHop(mu, seen, startTimes, out, rawHop{Target: target.Input, TTL: ttl, Addr: peer.String(), RTT: 0, Done: isDone, ReturnedHopLimit: returnedTTL, HasReturnedHopLimit: hasReturnedTTL, QuotedHopLimit: quotedTTL, HasQuotedHopLimit: true})
		if isDone {
			closeDone()
			return
		}
	}
}

func readTCPICMP6(pc *ipv6.PacketConn, target Target, maxHops int, opts TraceOptions, startTimes map[int]time.Time, mu *sync.Mutex, seen map[int]bool, done <-chan struct{}, closeDone func(), out chan<- rawHop, wg *sync.WaitGroup) {
	defer wg.Done()
	buf := make([]byte, 1500)
	for {
		select {
		case <-done:
			return
		default:
		}
		_ = pc.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, cm, peer, err := pc.ReadFrom(buf)
		if err != nil {
			continue
		}
		returnedHopLimit, hasReturnedHopLimit := 0, false
		if cm != nil && cm.HopLimit > 0 {
			returnedHopLimit, hasReturnedHopLimit = cm.HopLimit, true
		}
		rm, err := icmp.ParseMessage(58, buf[:n])
		if err != nil {
			continue
		}
		var ttl, quotedHopLimit int
		var ok, isDone bool
		switch rm.Type {
		case ipv6.ICMPTypeTimeExceeded:
			ttl, quotedHopLimit, ok = matchEmbeddedTCP6(rm.Body, target.Index, maxHops)
		case ipv6.ICMPTypeDestinationUnreachable:
			ttl, quotedHopLimit, ok = matchEmbeddedTCP6(rm.Body, target.Index, maxHops)
			isDone = ok
		}
		if !ok || ttl < 1 || ttl > maxHops {
			continue
		}
		emitSeenHop(mu, seen, startTimes, out, rawHop{Target: target.Input, TTL: ttl, Addr: peer.String(), RTT: 0, Done: isDone, ReturnedHopLimit: returnedHopLimit, HasReturnedHopLimit: hasReturnedHopLimit, QuotedHopLimit: quotedHopLimit, HasQuotedHopLimit: true})
		if isDone {
			closeDone()
			return
		}
	}
}

func dialTCPProbe(wg *sync.WaitGroup, mu *sync.Mutex, seen map[int]bool, done <-chan struct{}, closeDone func(), out chan<- rawHop, target Target, ttl int, sourcePort int, timeout time.Duration, opts TraceOptions, ipv6Target bool) {
	defer wg.Done()

	network := "tcp4"
	if ipv6Target {
		network = "tcp6"
	}
	local := &net.TCPAddr{IP: opts.SourceIP, Port: sourcePort}
	if ipv6Target && opts.Interface != "" {
		local.Zone = opts.Interface
	}
	dialer := net.Dialer{
		Timeout:   timeout,
		LocalAddr: local,
		Control:   tcpControl(opts.Interface, ttl, ipv6Target),
	}
	start := time.Now()
	conn, err := dialer.Dial(network, net.JoinHostPort(target.IP.String(), strconv.Itoa(opts.Port)))
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil || errors.Is(err, syscall.ECONNREFUSED) {
		mu.Lock()
		if seen[ttl] {
			mu.Unlock()
			return
		}
		seen[ttl] = true
		mu.Unlock()
		out <- rawHop{Target: target.Input, TTL: ttl, Addr: target.IP.String(), RTT: time.Since(start), Done: true}
		closeDone()
	}
}

func tcpControl(iface string, ttl int, ipv6Target bool) func(string, string, syscall.RawConn) error {
	return func(network string, address string, c syscall.RawConn) error {
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			if iface != "" {
				if err := unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface); err != nil {
					sockErr = err
					return
				}
			}
			if ipv6Target {
				sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, ttl)
			} else {
				sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, ttl)
			}
		}); err != nil {
			return err
		}
		if sockErr != nil {
			return fmt.Errorf("configure tcp probe socket: %w", sockErr)
		}
		return nil
	}
}

func startTimeout(wg *sync.WaitGroup, mu *sync.Mutex, seen map[int]bool, done <-chan struct{}, out chan<- rawHop, target string, ttl int, timeout time.Duration) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case <-timer.C:
			mu.Lock()
			if seen[ttl] {
				mu.Unlock()
				return
			}
			seen[ttl] = true
			mu.Unlock()
			out <- rawHop{Target: target, TTL: ttl, TimedOut: true}
		case <-done:
			return
		}
	}()
}

func emitSeenHop(mu *sync.Mutex, seen map[int]bool, startTimes map[int]time.Time, out chan<- rawHop, hop rawHop) bool {
	mu.Lock()
	if seen[hop.TTL] {
		mu.Unlock()
		return false
	}
	seen[hop.TTL] = true
	start := startTimes[hop.TTL]
	mu.Unlock()
	if start.IsZero() {
		return false
	}
	hop.RTT = time.Since(start)
	out <- hop
	return true
}

func waitForDone(done <-chan struct{}, timeout time.Duration) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-done:
	}
}

func validateSourceFamily(opts TraceOptions, ipv6Target bool) error {
	if opts.SourceIP == nil {
		return nil
	}
	if ipv6Target && opts.SourceIP.To4() != nil {
		return fmt.Errorf("-src %s is IPv4 but target is IPv6", opts.SourceIP)
	}
	if !ipv6Target && opts.SourceIP.To4() == nil {
		return fmt.Errorf("-src %s is IPv6 but target is IPv4", opts.SourceIP)
	}
	return nil
}

func listenAnyAddress(opts TraceOptions, ipv6Target bool) string {
	if opts.SourceIP == nil {
		if ipv6Target {
			return "::"
		}
		return "0.0.0.0"
	}
	if ipv6Target && opts.Interface != "" {
		return opts.SourceIP.String() + "%" + opts.Interface
	}
	return opts.SourceIP.String()
}

func udpListenAddress(opts TraceOptions, ipv6Target bool) string {
	if opts.SourceIP == nil {
		if ipv6Target {
			return "[::]:0"
		}
		return "0.0.0.0:0"
	}
	host := opts.SourceIP.String()
	if ipv6Target && opts.Interface != "" {
		host += "%" + opts.Interface
	}
	return net.JoinHostPort(host, "0")
}

func tcpSourcePort(targetIndex int, maxHops int, ttl int) int {
	return tcpSourceBase + targetIndex*maxHops + ttl
}

func ttlFromPort(port int, base int) (int, bool) {
	ttl := port - base + 1
	return ttl, ttl > 0
}

func ttlFromTCPSourcePort(port int, targetIndex int, maxHops int) (int, bool) {
	ttl := port - tcpSourceBase - targetIndex*maxHops
	return ttl, ttl > 0 && ttl <= maxHops
}

func matchEmbeddedUDP4(body icmp.MessageBody, basePort int) (ttl int, quotedTTL int, ok bool) {
	data := embeddedICMPData(body)
	if data == nil {
		return 0, 0, false
	}
	h, err := icmp.ParseIPv4Header(data)
	if err != nil || len(data) < h.Len+8 || h.Protocol != 17 {
		return 0, 0, false
	}
	dstPort := int(data[h.Len+2])<<8 | int(data[h.Len+3])
	ttl, ok = ttlFromPort(dstPort, basePort)
	return ttl, h.TTL, ok
}

func matchEmbeddedUDP6(body icmp.MessageBody, basePort int) (ttl int, quotedHopLimit int, ok bool) {
	data := embeddedICMPData(body)
	if len(data) < ipv6.HeaderLen+8 {
		return 0, 0, false
	}
	h, err := ipv6.ParseHeader(data)
	if err != nil || h.NextHeader != 17 {
		return 0, 0, false
	}
	dstPort := int(data[ipv6.HeaderLen+2])<<8 | int(data[ipv6.HeaderLen+3])
	ttl, ok = ttlFromPort(dstPort, basePort)
	return ttl, h.HopLimit, ok
}

func matchEmbeddedTCP4(body icmp.MessageBody, targetIndex int, maxHops int) (ttl int, quotedTTL int, ok bool) {
	data := embeddedICMPData(body)
	if data == nil {
		return 0, 0, false
	}
	h, err := icmp.ParseIPv4Header(data)
	if err != nil || len(data) < h.Len+20 || h.Protocol != 6 {
		return 0, 0, false
	}
	srcPort := int(data[h.Len])<<8 | int(data[h.Len+1])
	ttl, ok = ttlFromTCPSourcePort(srcPort, targetIndex, maxHops)
	return ttl, h.TTL, ok
}

func matchEmbeddedTCP6(body icmp.MessageBody, targetIndex int, maxHops int) (ttl int, quotedHopLimit int, ok bool) {
	data := embeddedICMPData(body)
	if len(data) < ipv6.HeaderLen+20 {
		return 0, 0, false
	}
	h, err := ipv6.ParseHeader(data)
	if err != nil || h.NextHeader != 6 {
		return 0, 0, false
	}
	srcPort := int(data[ipv6.HeaderLen])<<8 | int(data[ipv6.HeaderLen+1])
	ttl, ok = ttlFromTCPSourcePort(srcPort, targetIndex, maxHops)
	return ttl, h.HopLimit, ok
}

func embeddedICMPData(body icmp.MessageBody) []byte {
	switch b := body.(type) {
	case *icmp.TimeExceeded:
		return b.Data
	case *icmp.DstUnreach:
		return b.Data
	default:
		return nil
	}
}

func enrichLoop(in <-chan rawHop, out chan<- Hop, wg *sync.WaitGroup, geo *GeoLookup) {
	for r := range in {
		wg.Add(1)

		go func(r rawHop) {
			defer wg.Done()

			h := Hop{
				Target:              r.Target,
				TTL:                 r.TTL,
				Addr:                r.Addr,
				RTT:                 r.RTT,
				Done:                r.Done,
				TimedOut:            r.TimedOut,
				ReturnedHopLimit:    r.ReturnedHopLimit,
				HasReturnedHopLimit: r.HasReturnedHopLimit,
				QuotedHopLimit:      r.QuotedHopLimit,
				HasQuotedHopLimit:   r.HasQuotedHopLimit,
			}

			if !r.TimedOut && r.Addr != "" {
				ip := parseAddrIP(r.Addr)
				if ip != nil {
					h.AS, h.ASName, h.Country, h.City = geo.Lookup(ip)
				}
			}

			out <- h
		}(r)
	}
}

func printOrdered(in <-chan Hop, maxHops int, reorderWindow time.Duration) []Hop {
	next := 1
	buffer := make(map[int]Hop)
	printed := make(map[int]bool)
	results := make([]Hop, 0, maxHops)

	var timer *time.Timer
	var timerC <-chan time.Time

	startTimer := func() {
		if timer == nil {
			timer = time.NewTimer(reorderWindow)
			timerC = timer.C
			return
		}

		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}

		timer.Reset(reorderWindow)
		timerC = timer.C
	}

	stopTimer := func() {
		if timer == nil {
			return
		}

		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}

		timerC = nil
	}

	emit := func(h Hop) bool {
		printHop(h)
		results = append(results, h)
		printed[h.TTL] = true
		return h.Done
	}

	printContiguous := func() bool {
		for {
			h, ok := buffer[next]
			if !ok {
				return false
			}

			delete(buffer, next)

			done := emit(h)
			if done {
				return true
			}

			next++
		}
	}

	printLowestAvailable := func() bool {
		if len(buffer) == 0 {
			return false
		}

		keys := make([]int, 0, len(buffer))
		for ttl := range buffer {
			keys = append(keys, ttl)
		}

		sort.Ints(keys)

		ttl := keys[0]
		h := buffer[ttl]
		delete(buffer, ttl)

		if ttl > next {
			next = ttl
		}

		done := emit(h)
		next = ttl + 1

		return done
	}

	for {
		select {
		case h, ok := <-in:
			if !ok {
				stopTimer()

				for len(buffer) > 0 {
					done := printLowestAvailable()
					if done {
						return results
					}
				}

				return results
			}

			if printed[h.TTL] {
				continue
			}

			if h.TTL < next {
				h.Late = true
				done := emit(h)
				if done {
					return results
				}
				continue
			}

			buffer[h.TTL] = h

			if h.TTL == next {
				done := printContiguous()
				if done {
					return results
				}

				if len(buffer) == 0 {
					stopTimer()
				} else {
					startTimer()
				}
			} else {
				startTimer()
			}

		case <-timerC:
			done := printLowestAvailable()
			if done {
				return results
			}

			done = printContiguous()
			if done {
				return results
			}

			if len(buffer) > 0 {
				startTimer()
			} else {
				stopTimer()
			}
		}
	}
}

func printHop(h Hop) {
	if h.TimedOut {
		fmt.Printf(
			rowFormat,
			h.TTL,
			"*",
			"-",
			"-",
			"-",
			"-",
			"*",
			"-",
			"-",
		)
		return
	}

	addr := h.Addr
	if h.Late {
		addr = addr + " late"
	}

	fmt.Printf(
		rowFormat,
		h.TTL,
		trunc(addr, colAddress),
		trunc(defaultDash(h.AS), colAS),
		trunc(defaultDash(h.ASName), colASName),
		trunc(defaultDash(h.Country), colCountry),
		trunc(defaultDash(h.City), colCity),
		h.RTT.Round(time.Microsecond),
		formatMaybeInt(h.ReturnedHopLimit, h.HasReturnedHopLimit),
		formatMaybeInt(h.QuotedHopLimit, h.HasQuotedHopLimit),
	)
}

func openCSVOutput(path string, identifyMode bool) (*CSVOutput, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create output file: %w", err)
	}

	out := &CSVOutput{
		writer: csv.NewWriter(f),
		file:   f,
	}

	header := []string{
		"target",
		"hop",
		"address",
		"as",
		"as_name",
		"country",
		"city",
		"rtt_us",
		"reply_ttl_hlim",
		"quoted_ttl_hlim",
		"timed_out",
		"done",
		"late",
	}

	if identifyMode {
		header = append(
			header,
			"trigger_final_hop",
			"trigger_final_address",
			"trigger_final_quoted_ttl_hlim",
		)
	}

	if err := out.writer.Write(header); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("write CSV header: %w", err)
	}

	out.writer.Flush()
	if err := out.writer.Error(); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("flush CSV header: %w", err)
	}

	return out, nil
}

func (c *CSVOutput) Close() {
	if c == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.writer != nil {
		c.writer.Flush()
	}

	if c.file != nil {
		_ = c.file.Close()
	}
}

func (c *CSVOutput) WriteHopRows(target string, hops []Hop) error {
	if c == nil {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for _, h := range hops {
		if err := c.writer.Write(csvRow(target, h)); err != nil {
			return err
		}
	}

	c.writer.Flush()
	return c.writer.Error()
}

func (c *CSVOutput) WriteIdentifyRows(target string, hops []Hop) error {
	if c == nil {
		return nil
	}

	finalIdx := finalObservedHopIndex(hops)
	if finalIdx <= 0 {
		return nil
	}

	final := hops[finalIdx]
	if !final.HasQuotedHopLimit || final.QuotedHopLimit <= 1 {
		return nil
	}

	prevIdx := previousObservedHopIndex(hops, finalIdx)
	if prevIdx < 0 {
		return nil
	}

	prev := hops[prevIdx]

	row := csvRow(target, prev)
	row = append(
		row,
		strconv.Itoa(final.TTL),
		final.Addr,
		formatMaybeInt(final.QuotedHopLimit, final.HasQuotedHopLimit),
	)

	c.mu.Lock()
	defer c.mu.Unlock()

	if err := c.writer.Write(row); err != nil {
		return err
	}

	c.writer.Flush()
	return c.writer.Error()
}

func finalObservedHopIndex(hops []Hop) int {
	if len(hops) == 0 {
		return -1
	}

	for i := range hops {
		if hops[i].Done {
			return i
		}
	}

	for i := len(hops) - 1; i >= 0; i-- {
		if !hops[i].TimedOut {
			return i
		}
	}

	return len(hops) - 1
}

func previousObservedHopIndex(hops []Hop, before int) int {
	for i := before - 1; i >= 0; i-- {
		if !hops[i].TimedOut {
			return i
		}
	}

	if before > 0 {
		return before - 1
	}

	return -1
}

func csvRow(target string, h Hop) []string {
	return []string{
		target,
		strconv.Itoa(h.TTL),
		h.Addr,
		h.AS,
		h.ASName,
		h.Country,
		h.City,
		strconv.FormatInt(h.RTT.Microseconds(), 10),
		formatMaybeInt(h.ReturnedHopLimit, h.HasReturnedHopLimit),
		formatMaybeInt(h.QuotedHopLimit, h.HasQuotedHopLimit),
		strconv.FormatBool(h.TimedOut),
		strconv.FormatBool(h.Done),
		strconv.FormatBool(h.Late),
	}
}

func trunc(s string, width int) string {
	if len(s) <= width {
		return s
	}

	if width <= 1 {
		return s[:width]
	}

	return s[:width-1] + "…"
}

func formatMaybeInt(v int, ok bool) string {
	if !ok {
		return ""
	}
	return fmt.Sprintf("%d", v)
}

func defaultDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func parseAddrIP(addr string) net.IP {
	if addr == "" {
		return nil
	}

	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return net.ParseIP(host)
	}

	if strings.HasPrefix(addr, "[") && strings.Contains(addr, "]") {
		addr = strings.TrimPrefix(addr, "[")
		addr = strings.Split(addr, "]")[0]
	}

	return net.ParseIP(addr)
}

func openGeoLookup(cityPath, asnPath string) (*GeoLookup, error) {
	g := &GeoLookup{}

	if cityPath != "" {
		db, err := maxminddb.Open(cityPath)
		if err != nil {
			return nil, fmt.Errorf("open city MMDB: %w", err)
		}
		g.cityDB = db
	}

	if asnPath != "" {
		db, err := maxminddb.Open(asnPath)
		if err != nil {
			return nil, fmt.Errorf("open ASN MMDB: %w", err)
		}
		g.asnDB = db
	}

	return g, nil
}

func (g *GeoLookup) Close() {
	if g == nil {
		return
	}

	if g.cityDB != nil {
		_ = g.cityDB.Close()
	}

	if g.asnDB != nil {
		_ = g.asnDB.Close()
	}
}

func (g *GeoLookup) Lookup(ip net.IP) (as string, asName string, country string, city string) {
	if g == nil || ip == nil {
		return "", "", "", ""
	}

	if g.asnDB != nil {
		var rec map[string]interface{}
		if err := g.asnDB.Lookup(ip, &rec); err == nil {
			as, asName = extractASN(rec)
		}
	}

	if g.cityDB != nil {
		var rec map[string]interface{}
		if err := g.cityDB.Lookup(ip, &rec); err == nil {
			country = firstString(
				valueAt(rec, "country_name"),
				valueAt(rec, "country"),
				valueAt(rec, "country.iso_code"),
				valueAt(rec, "registered_country.iso_code"),
				valueAt(rec, "location.country"),
			)

			city = firstString(
				valueAt(rec, "city_name"),
				valueAt(rec, "city"),
				valueAt(rec, "city.names.en"),
				valueAt(rec, "location.city"),
			)
		}
	}

	return as, asName, country, city
}

func extractASN(rec map[string]interface{}) (as string, asName string) {
	rawAS := firstString(
		valueAt(rec, "asn"),
		valueAt(rec, "autonomous_system_number"),
		valueAt(rec, "traits.autonomous_system_number"),
	)

	asName = firstString(
		valueAt(rec, "as_name"),
		valueAt(rec, "autonomous_system_organization"),
		valueAt(rec, "traits.autonomous_system_organization"),
		valueAt(rec, "name"),
	)

	if rawAS == "" {
		return "", asName
	}

	if strings.HasPrefix(strings.ToUpper(rawAS), "AS") {
		return rawAS, asName
	}

	return "AS" + rawAS, asName
}

func valueAt(rec map[string]interface{}, path string) interface{} {
	var cur interface{} = rec

	for _, p := range strings.Split(path, ".") {
		m, ok := cur.(map[string]interface{})
		if !ok {
			return nil
		}

		cur = m[p]
		if cur == nil {
			return nil
		}
	}

	return cur
}

func firstString(values ...interface{}) string {
	for _, v := range values {
		s := stringify(v)
		if s != "" {
			return s
		}
	}

	return ""
}

func stringify(v interface{}) string {
	switch x := v.(type) {
	case nil:
		return ""

	case string:
		return x

	case []byte:
		return string(x)

	case int:
		return strconv.Itoa(x)

	case int32:
		return strconv.FormatInt(int64(x), 10)

	case int64:
		return strconv.FormatInt(x, 10)

	case uint:
		return strconv.FormatUint(uint64(x), 10)

	case uint16:
		return strconv.FormatUint(uint64(x), 10)

	case uint32:
		return strconv.FormatUint(uint64(x), 10)

	case uint64:
		return strconv.FormatUint(x, 10)

	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)

	default:
		return ""
	}
}
