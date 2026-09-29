package scan

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"syscall"
	"time"

	storage "iocscanner/src/db"

	"golang.org/x/sys/unix"
)

// ScanTimeouts is the three budgets a pass runs under, folded into one value so probePort takes
// four parameters rather than six.
type ScanTimeouts struct{ Dial, TLS, JARM time.Duration }

// errnoName renders a dial failure as EADDRNOTAVAIL rather than "can't assign requested address",
// so the cause is one grep-able token. Anything without an errno keeps its own message.
func errnoName(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		if name := unix.ErrnoName(errno); name != "" {
			return name
		}
	}
	return err.Error()
}

// IsRDP sends an RDP negotiation request and recognizes the X.224 Connection Confirm prefix.
func IsRDP(conn net.Conn) (bool, error) {
	const request = "\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00"
	if _, err := io.WriteString(conn, request); err != nil {
		return false, err
	}
	var response [7]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		return false, err
	}
	return response[0] == 0x03 && response[1] == 0x00 && response[5] == 0xd0, nil
}

// probeState is which tally a dial belongs to.
type probeState int

// StageTiming is what one stage of a probe measured. Plain fields rather than atomics: a probe
// fills in its own and hands it back, so no two goroutines ever touch one.
type StageTiming struct {
	samples            []time.Duration
	Timeouts, failures int64
}

func (s *StageTiming) ok(took time.Duration) { s.samples = append(s.samples, took) }

func (s *StageTiming) timedOut() { s.Timeouts++ }

func (s *StageTiming) failed() { s.failures++ }

// probeOutcome is everything one dial did. Returned rather than written into the pass, so a probe
// measures itself and the fold into the sweep's counters happens in exactly one place.
type probeOutcome struct {
	State probeState
	// row is set for an open port only. err is set for probeUntested only.
	Row *storage.Scan
	Err error
	// slot is the worker-slot time the probe cost. The caller releases its max_workers slot the
	// moment probePort returns, so this is what the sweep actually spent on the port — dial,
	// handshake and all ten JARM probes — rather than the round trip of the SYN alone.
	slot time.Duration
	// dial is the time to the answer, set for an open port. complete covers the whole probe and is
	// set only where the dial, the handshake and every JARM probe finished; a port that stopped
	// short would otherwise read as a fast complete.
	dial, complete time.Duration
	tls, jarm      StageTiming
}

// ProbePort dials one port, checks for RDP on 3389, and otherwise collects TLS and JARM data.
// Everything it measured comes back in the outcome; nothing about the sweep reaches in here.
func ProbePort(ctx context.Context, target netip.AddrPort, timeouts ScanTimeouts) (out probeOutcome) {
	start := time.Now()
	// One defer for every return path, so no exit can forget to charge its slot time.
	defer func() {
		out.slot = time.Since(start)
		if out.Row != nil && out.Row.JARM != "" {
			out.complete = out.slot
		}
	}()
	dialer := &net.Dialer{Timeout: timeouts.Dial}
	conn, err := dialer.DialContext(ctx, "tcp", target.String())
	if err != nil {
		if ctx.Err() != nil {
			out.State, out.Err = probeUntested, ctx.Err()
			return out
		}
		// Only the local stack running out of something means the port was never tested. Every
		// other errno is the network answering — refused, no route, reset — which is a real
		// result about the port, not a gap in the pass.
		var errno syscall.Errno
		if errors.As(err, &errno) && slices.Contains(localLimits, errno) {
			out.State, out.Err = probeUntested, errno
			return out
		}
		var timeout net.Error
		if errors.As(err, &timeout) && timeout.Timeout() {
			out.State = probeFiltered
		} else {
			out.State = ProbeClosed
		}
		return out
	}
	out.State = probeOpen
	out.dial = time.Since(start)
	row := storage.Scan{IP: target.Addr().String(), Port: int(target.Port()), IsOpen: true,
		ScannedAt: time.Now().Unix()}
	out.Row = &row
	// A port 3389 confirmed as RDP returns before any handshake and so contributes no TLS or JARM
	// counts. The redial below, on a non-RDP answer, is a second dial inside this same slot: it is
	// charged to the slot time but not counted as a second open port.
	if target.Port() == 3389 {
		conn.SetDeadline(time.Now().Add(timeouts.TLS))
		rdp, _ := IsRDP(conn)
		conn.Close()
		if rdp {
			return out
		}
		conn, err = dialer.DialContext(ctx, "tcp", target.String())
		if err != nil {
			return out
		}
	}
	defer conn.Close()

	// The handshake gets its own budget, not what is left of the dial's. A host slow enough to
	// need most of dial_timeout_ms to answer is the one whose certificate was being lost.
	conn.SetDeadline(time.Now().Add(timeouts.TLS))
	// InsecureSkipVerify is deliberate. Expired and self-signed certs are what this hunts for.
	// No ServerName: targets are bare IPs with no SNI to send, so the server answers with its
	// default vhost cert. MinVersion is TLS 1.0 because Go refuses below 1.2 by default, and old
	// C2 hosts still serve 1.0 and 1.1.
	client := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10})
	handshake := time.Now()
	err = client.HandshakeContext(ctx)
	if err != nil {
		// Only a real deadline is a timeout. A rejected handshake or a peer that does not speak
		// TLS at all comes back at once and says nothing about whether tls_timeout_ms is tight.
		if errors.Is(err, os.ErrDeadlineExceeded) {
			out.tls.timedOut()
		} else {
			out.tls.failed()
		}
		// An open port with no certificate is the same row whether the peer does not speak TLS or
		// the handshake was cut off. Only the error tells them apart. Not a return: it falls
		// through to the close-and-return shared with the certificate path below.
		slog.Debug("tls handshake failed", "ip", row.IP, "port", row.Port, "err", err)
	} else {
		out.tls.ok(time.Since(handshake))
		if certs := client.ConnectionState().PeerCertificates; len(certs) > 0 {
			// PeerCertificates[0] is the leaf. The rest is the chain the server presented.
			row.Subject, row.Issuer = certs[0].Subject.CommonName, certs[0].Issuer.CommonName
			row.DNSNames = strings.Join(certs[0].DNSNames, ",")
			row.NotBefore, row.NotAfter = certs[0].NotBefore.Unix(), certs[0].NotAfter.Unix()
			row.SignatureAlgorithm = certs[0].SignatureAlgorithm.String()
			row.SerialNumber = certs[0].SerialNumber.String()
			// Verified against itself rather than compared by CN. A certificate can carry the same
			// CN on both sides without being self-signed, and vice versa.
			row.SelfSigned = certs[0].CheckSignatureFrom(certs[0]) == nil || row.Subject == row.Issuer
			// SHA-1 over the DER, which is the fingerprint SSLBL lists.
			sum := sha1.Sum(certs[0].Raw)
			row.Fingerprint = hex.EncodeToString(sum[:])
		}
	}

	// Closed here, not left to the defer. The probes below dial this same target ten times, and a
	// server that handles one connection at a time answers none of them while this socket is still
	// open — it is blocked on us. Every probe then times out and the fingerprint comes back all
	// zeroes, which reads as a port that does not speak TLS. The defer stays as the backstop for the
	// paths above; a second Close is just ErrClosed.
	conn.Close()

	// Only a port that completed the handshake is fingerprinted. A failed one means the port does
	// not speak TLS, and ten more dials would only confirm it at ten times the cost.
	//
	// One host can still have several of its ports in flight at once: the max_workers semaphore is
	// global and the sweep walks ports outermost. A single-threaded server bound to more than one
	// port can therefore still starve its own probes from the neighbouring port. Serializing per
	// host would slow every multi-port host to rescue a rare one, so it is left alone.
	if err == nil {
		row.JARM, out.jarm, err = FingerprintJARM(ctx, target, timeouts.JARM)
		if err != nil {
			slog.Debug("jarm fingerprint failed", "ip", row.IP, "port", row.Port, "err", err)
		}
	}
	return out
}

// localLimits are the dial failures that mean this machine ran out of something: descriptors,
// ephemeral ports, socket buffers. They are the only errnos that leave a port untested, and the
// only ones worth a warning — the operator can fix them with ulimit -n or max_workers.
// EHOSTUNREACH, ENETUNREACH, ECONNRESET and ECONNREFUSED are the remote end or the path
// answering, and belong with the closed ports.
var localLimits = []syscall.Errno{
	syscall.EMFILE,        // process descriptor limit
	syscall.ENFILE,        // system-wide descriptor limit
	syscall.EADDRNOTAVAIL, // ephemeral port range exhausted
	syscall.ENOBUFS,       // no socket buffer space
	syscall.ENOMEM,        // out of kernel memory
	syscall.EAGAIN,        // no free local port (Linux spells this EAGAIN on connect)
}

const (
	// probeClosed is the network answering: refused, no route, reset. A real result about the port.
	ProbeClosed probeState = iota
	// probeFiltered is a dial that ran out its budget without an answer. It costs the whole of
	// dial_timeout_ms, where a refusal comes back at once, and splitting the two is the only way
	// the cost of that setting is visible.
	probeFiltered
	probeOpen
	// probeUntested is the local stack running out of something. The port was never tested, so
	// stored state must not move.
	probeUntested
)
