//go:build windows

package udp2raw

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	errPermission = windows.ERROR_ACCESS_DENIED
	errAccess     = windows.ERROR_ACCESS_DENIED
)

// ErrWinDivertMissing means the WinDivert driver/DLL could not be loaded.
var ErrWinDivertMissing = errors.New(
	"udp2raw: WinDivert not found; place WinDivert.dll and WinDivert64.sys next to the executable " +
		"(download from https://github.com/basil00/WinDivert/releases)",
)

const (
	windivertLayerNetwork  = 0
	windivertInvalidHandle = ^uintptr(0)

	windivertParamQueueLength = 0
	windivertParamQueueTime   = 1
	windivertParamQueueSize   = 2
)

var (
	windivertOnce sync.Once
	windivertErr  error
	wdOpen        *syscall.LazyProc
	wdRecv        *syscall.LazyProc
	wdSend        *syscall.LazyProc
	wdClose       *syscall.LazyProc
	wdSetParam    *syscall.LazyProc
)

func loadWinDivert() error {
	windivertOnce.Do(func() {
		dll := syscall.NewLazyDLL("WinDivert.dll")
		if err := dll.Load(); err != nil {
			windivertErr = fmt.Errorf("%w: %v", ErrWinDivertMissing, err)
			return
		}
		wdOpen = dll.NewProc("WinDivertOpen")
		wdRecv = dll.NewProc("WinDivertRecv")
		wdSend = dll.NewProc("WinDivertSend")
		wdClose = dll.NewProc("WinDivertClose")
		wdSetParam = dll.NewProc("WinDivertSetParam")
	})
	return windivertErr
}

// faketcpPlatformSupported reports whether "auto" should try faketcp here.
// On Windows the backend needs the WinDivert driver, so auto prefers tcp and
// faketcp must be requested explicitly.
func faketcpPlatformSupported() bool { return false }

type windowsEndpoint struct {
	filter endpointFilter
	handle uintptr

	buf     []byte
	addr    [64]byte
	recvLen uint32
	sendLen uint32

	closed  bool
	closeMu sync.Mutex
}

func openRawEndpoint(f endpointFilter) (rawEndpoint, error) {
	if err := loadWinDivert(); err != nil {
		return nil, err
	}
	filterStr := "inbound and tcp and tcp.DstPort == " + itoa(f.listenPort)
	if !f.server {
		filterStr = "inbound and tcp and tcp.SrcPort == " + itoa(f.serverPort) +
			" and tcp.DstPort == " + itoa(f.localPort)
	}
	if f.server && f.listenIP.IsValid() && !f.listenIP.IsUnspecified() {
		filterStr += " and ip.DstAddr == " + f.listenIP.String()
	}
	filterBytes := append([]byte(filterStr), 0)
	handle, _, err := wdOpen.Call(
		uintptr(unsafe.Pointer(&filterBytes[0])),
		uintptr(windivertLayerNetwork),
		0,
		0,
	)
	if handle == windivertInvalidHandle || handle == 0 {
		if err == nil {
			err = windows.ERROR_ACCESS_DENIED
		}
		return nil, mapSockErr(err)
	}
	e := &windowsEndpoint{filter: f, handle: handle, buf: make([]byte, 65536)}
	// Large queue so bursts are not dropped while the reader is busy.
	_, _, _ = wdSetParam.Call(handle, windivertParamQueueLength, 8192)
	_, _, _ = wdSetParam.Call(handle, windivertParamQueueTime, 2000)
	_, _, _ = wdSetParam.Call(handle, windivertParamQueueSize, 4<<20)
	return e, nil
}

func (e *windowsEndpoint) recv() (segment, error) {
	for {
		var ok uintptr
		var err error
		ok, _, err = wdRecv.Call(
			e.handle,
			uintptr(unsafe.Pointer(&e.buf[0])),
			uintptr(len(e.buf)),
			uintptr(unsafe.Pointer(&e.recvLen)),
			uintptr(unsafe.Pointer(&e.addr[0])),
		)
		if ok == 0 {
			e.closeMu.Lock()
			closed := e.closed
			e.closeMu.Unlock()
			if closed {
				return segment{}, net.ErrClosed
			}
			if errors.Is(err, windows.ERROR_NO_DATA) {
				continue
			}
			return segment{}, mapSockErr(err)
		}
		seg, okParse := parseSegment(e.buf[:e.recvLen])
		if !okParse || !e.match(seg) {
			continue
		}
		return seg, nil
	}
}

func (e *windowsEndpoint) match(seg segment) bool {
	if e.filter.server {
		if seg.Dst.Port() != uint16(e.filter.listenPort) {
			return false
		}
		if e.filter.listenIP.IsValid() && !e.filter.listenIP.IsUnspecified() &&
			seg.Dst.Addr() != e.filter.listenIP {
			return false
		}
		return true
	}
	return seg.Src == netip.AddrPortFrom(e.filter.serverIP, uint16(e.filter.serverPort)) &&
		seg.Dst.Addr() == e.filter.localIP
}

func (e *windowsEndpoint) send(pkt []byte) error {
	var addr [64]byte
	// Outbound bit (bit 17 of the layer/event/flags word) tells the driver to
	// inject the packet into the outbound path rather than deliver it locally.
	addr[10] |= 0x02
	e.sendLen = 0
	ok, _, err := wdSend.Call(
		e.handle,
		uintptr(unsafe.Pointer(&pkt[0])),
		uintptr(len(pkt)),
		uintptr(unsafe.Pointer(&e.sendLen)),
		uintptr(unsafe.Pointer(&addr[0])),
	)
	if ok == 0 {
		if err == nil {
			err = windows.ERROR_ACCESS_DENIED
		}
		return mapSockErr(err)
	}
	return nil
}

func (e *windowsEndpoint) close() error {
	e.closeMu.Lock()
	defer e.closeMu.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	_, _, _ = wdClose.Call(e.handle)
	return nil
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b [6]byte
	i := len(b)
	for v > 0 && i > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
