package pgstore

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/jackc/pgx/v5/pgproto3"
)

// errNotSCRAM is the fixed refusal when a server asks for anything but a
// complete SCRAM-SHA-256 exchange. It carries no server text.
var errNotSCRAM = errors.New("pgstore: server did not offer SCRAM-SHA-256 authentication")

// maxAuthMessage bounds a single backend message before authentication ends.
const maxAuthMessage = 64 * 1024

// scramOnlyFrontend makes pgx enforce SCRAM-only authentication. pgx has no
// equivalent of libpq's require_auth (and a same-named DSN key is not honoured
// by pgx), so the backend stream — after TLS, i.e. the decrypted protocol — is
// checked one whole message at a time BEFORE pgx sees it:
//
//   - AuthenticationSASL must list SCRAM-SHA-256; SASLContinue/SASLFinal must
//     follow in order; AuthenticationOk is accepted only after SASLFinal (pgx
//     itself verifies the server signature carried by SASLFinal).
//   - Cleartext, MD5, GSS/SSPI, Kerberos or any other request, and anything a
//     server sends instead of authenticating (e.g. ReadyForQuery or an
//     AuthenticationOk without SCRAM), fail the read. pgx then closes the
//     connection without ever sending a PasswordMessage.
//
// Once AuthenticationOk is accepted the stream passes through unchanged.
func scramOnlyFrontend(r io.Reader, w io.Writer) *pgproto3.Frontend {
	return pgproto3.NewFrontend(&scramOnlyReader{r: r}, w)
}

type scramOnlyReader struct {
	r               io.Reader
	pending         []byte
	done            bool
	err             error
	sasl, saslFinal bool
}

func (g *scramOnlyReader) Read(p []byte) (int, error) {
	if len(g.pending) > 0 {
		n := copy(p, g.pending)
		g.pending = g.pending[n:]
		return n, nil
	}
	if g.done {
		return g.r.Read(p)
	}
	if g.err != nil {
		return 0, g.err
	}
	header := make([]byte, 5)
	if _, err := io.ReadFull(g.r, header); err != nil {
		return 0, err
	}
	size := binary.BigEndian.Uint32(header[1:])
	if size < 4 || size > maxAuthMessage {
		g.err = errNotSCRAM
		return 0, g.err
	}
	body := make([]byte, size-4)
	if _, err := io.ReadFull(g.r, body); err != nil {
		return 0, err
	}
	if err := g.check(header[0], body); err != nil {
		g.err = err
		return 0, err
	}
	g.pending = append(header, body...)
	return g.Read(p)
}

func (g *scramOnlyReader) check(kind byte, body []byte) error {
	switch kind {
	case 'E', 'N', 'v': // error/notice/protocol negotiation: no credential is requested
		return nil
	case 'R':
	default:
		return errNotSCRAM
	}
	if len(body) < 4 {
		return errNotSCRAM
	}
	switch binary.BigEndian.Uint32(body) {
	case 10: // AuthenticationSASL
		if g.sasl || !hasMechanism(body[4:], "SCRAM-SHA-256") {
			return errNotSCRAM
		}
		g.sasl = true
	case 11: // AuthenticationSASLContinue
		if !g.sasl || g.saslFinal {
			return errNotSCRAM
		}
	case 12: // AuthenticationSASLFinal
		if !g.sasl || g.saslFinal {
			return errNotSCRAM
		}
		g.saslFinal = true
	case 0: // AuthenticationOk
		if !g.saslFinal || len(body) != 4 {
			return errNotSCRAM
		}
		g.done = true
	default:
		return errNotSCRAM
	}
	return nil
}

func hasMechanism(list []byte, name string) bool {
	for _, m := range bytes.Split(list, []byte{0}) {
		if string(m) == name {
			return true
		}
	}
	return false
}
