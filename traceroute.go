// main.go
package main

import (
	"bufio"
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
	"time"

	"github.com/oschwald/maxminddb-golang"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
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
	Input  string
	IP    net.IP
	IPv6  bool
	Index int
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

		fmt.Printf("traceroute to %s, %d hops max\n", target.IP, *maxHops)
		printHeader()

		hops, err := runTraceroute(target, *maxHops, *timeout, *sendInterval, *reorderWindow, geo)
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
			Input:  input,
			IP:     ip,
			IPv6:   isIPv6,
			Index:  i,
		})
	}

	return targets, nil
}

func runTraceroute(target Target, maxHops int, timeout time.Duration, sendInterval time.Duration, reorderWindow time.Duration, geo *GeoLookup) ([]Hop, error) {
	rawCh := make(chan rawHop, maxHops*4)
	enrichedCh := make(chan Hop, maxHops*4)

	var geoWG sync.WaitGroup

	go enrichLoop(rawCh, enrichedCh, &geoWG, geo)

	printDone := make(chan []Hop, 1)

	go func() {
		printDone <- printOrdered(enrichedCh, maxHops, reorderWindow)
	}()

	var err error
	if target.IPv6 {
		err = trace6(target, maxHops, timeout, sendInterval, rawCh)
	} else {
		err = trace4(target, maxHops, timeout, sendInterval, rawCh)
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

func trace4(target Target, maxHops int, timeout time.Duration, sendInterval time.Duration, out chan<- rawHop) error {
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return err
	}
	defer c.Close()

	pc := c.IPv4PacketConn()
	if pc == nil {
		return errors.New("failed to get IPv4 packet connection")
	}

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

func trace6(target Target, maxHops int, timeout time.Duration, sendInterval time.Duration, out chan<- rawHop) error {
	c, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return err
	}
	defer c.Close()

	pc := c.IPv6PacketConn()
	if pc == nil {
		return errors.New("failed to get IPv6 packet connection")
	}

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
