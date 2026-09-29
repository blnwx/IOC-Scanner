package scan

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"time"

	jarm "github.com/hdm/jarm-go"
)

// FingerprintJARM fingerprints the TLS stack behind target by replaying the ten crafted
// ClientHellos JARM is built from and hashing what comes back. It identifies the server's TLS
// implementation and how it is configured, not its certificate, so it survives the certificate
// rotation that defeats a fingerprint feed.
//
// An empty string means nothing answered any probe. jarm-go renders that case as ZeroHash, which
// carries no information about the server: stored, it would be one meaningless row that every
// silent port collapses onto.
func FingerprintJARM(ctx context.Context, target netip.AddrPort, timeout time.Duration) (string, StageTiming, error) {
	probes := jarm.GetProbes(target.Addr().String(), int(target.Port()))
	results := make([]string, 0, len(probes))
	var timing StageTiming
	for _, probe := range probes {
		// One dial at a time. The caller holds a single max_workers slot for this whole call,
		// so ten at once would put the sweep that far over the cap it just took a slot from.
		result, err := SendJARMProbe(ctx, target, probe, timeout, &timing)
		if err != nil || ctx.Err() != nil {
			return "", timing, err
		}
		results = append(results, result)
	}
	hash := jarm.RawHashToFuzzyHash(strings.Join(results, ","))
	if hash == jarm.ZeroHash {
		return "", timing, fmt.Errorf("jarm zero hash")
	}
	return hash, timing, nil
}

// SendJARMProbe returns an empty answer for a response JARM cannot parse, and an error for
// transport failures. The latter abandons the whole fingerprint so a partial run cannot look rare.
//
// It also times itself into timing, per probe rather than per fingerprint. Only a real deadline
// counts as a timeout; other dial failures, failed writes, EOF and resets are separate failures.
func SendJARMProbe(ctx context.Context, target netip.AddrPort, probe jarm.JarmProbeOptions, timeout time.Duration, timing *StageTiming) (string, error) {
	start := time.Now()
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", target.String())
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
			timing.timedOut()
		} else {
			timing.failed()
		}
		return "|||", nil
	}
	defer conn.Close()
	// The response gets its own budget, not what is left of the dial's. Shared, a host slow to
	// answer the SYN has nothing left to send its ServerHello in, and every probe reads as silence.
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		timing.failed()
		return "", err
	}

	payload := jarm.BuildProbe(probe)
	if _, err := conn.Write(payload); err != nil {
		timing.failed()
		return "|||", nil
	}

	buf := make([]byte, 1484)

	// Record header.
	n, err := io.ReadFull(conn, buf[:5])
	if err != nil {
		if benignRead(err) {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				timing.timedOut()
			} else {
				timing.failed()
			}
			return "|||", nil
		}
		timing.failed()
		return "", err
	}

	// Remainder of the first record, clamped to the ceiling.
	recLen := int(binary.BigEndian.Uint16(buf[3:5]))
	if 5+recLen > len(buf) {
		recLen = len(buf) - 5
	}
	rest, err := io.ReadFull(conn, buf[5:5+recLen])
	n += rest
	if err != nil {
		if !benignRead(err) {
			timing.failed()
			return "", err
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			timing.timedOut()
		} else {
			timing.failed()
		}
		return jarm.ParseServerHello(buf[:n], probe)
	}

	// Drain the rest of the server's flight (Certificate, ServerKeyExchange,
	// ServerHelloDone) that Python's single recv would have picked up. Short
	// deadline so a server that stalls waiting for our ClientKeyExchange
	// doesn't burn the full timeout.
	_ = conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	for n < len(buf) {
		r, rerr := conn.Read(buf[n:])
		n += r
		if rerr != nil {
			break
		}
	}

	timing.ok(time.Since(start))
	return jarm.ParseServerHello(buf[:n], probe)
}

func benignRead(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, os.ErrDeadlineExceeded) ||
		errors.Is(err, syscall.ECONNRESET)
}
