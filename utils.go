//go:build linux
// +build linux

package iouring

import (
	"syscall"
	"unsafe"
)

var zero uintptr

func bytes2iovec(bs [][]byte) []syscall.Iovec {
	iovecs := make([]syscall.Iovec, len(bs))
	for i, b := range bs {
		iovecs[i].SetLen(len(b))
		if len(b) > 0 {
			iovecs[i].Base = &b[0]
		} else {
			iovecs[i].Base = (*byte)(unsafe.Pointer(&zero))
		}
	}
	return iovecs
}

// sockaddr converts a syscall.Sockaddr to a pointer and length
func sockaddr(addr syscall.Sockaddr) (unsafe.Pointer, uint32, error) {
	if addr == nil {
		return unsafe.Pointer(uintptr(0)), 0, nil
	}

	switch sa := addr.(type) {
	case *syscall.SockaddrInet4:
		var raw syscall.RawSockaddrInet4
		raw.Family = syscall.AF_INET
		p := (*[2]byte)(unsafe.Pointer(&raw.Port))
		p[0] = byte(sa.Port >> 8)
		p[1] = byte(sa.Port)
		for i := 0; i < len(sa.Addr); i++ {
			raw.Addr[i] = sa.Addr[i]
		}
		return unsafe.Pointer(&raw), syscall.SizeofSockaddrInet4, nil

	case *syscall.SockaddrInet6:
		var raw syscall.RawSockaddrInet6
		raw.Family = syscall.AF_INET6
		p := (*[2]byte)(unsafe.Pointer(&raw.Port))
		p[0] = byte(sa.Port >> 8)
		p[1] = byte(sa.Port)
		raw.Scope_id = sa.ZoneId
		for i := 0; i < len(sa.Addr); i++ {
			raw.Addr[i] = sa.Addr[i]
		}
		return unsafe.Pointer(&raw), syscall.SizeofSockaddrInet6, nil

	case *syscall.SockaddrUnix:
		name := sa.Name
		n := len(name)
		var raw syscall.RawSockaddrUnix
		if n > len(raw.Path) {
			return unsafe.Pointer(uintptr(0)), 0, syscall.EINVAL
		}
		raw.Family = syscall.AF_UNIX
		for i := 0; i < n; i++ {
			raw.Path[i] = int8(name[i])
		}
		// length is family (uint16), name, NUL.
		sl := _Socklen(2 + n + 1)
		if err := roundup(&sl); err != nil {
			return unsafe.Pointer(uintptr(0)), 0, err
		}
		return unsafe.Pointer(&raw), uint32(sl), nil
	}
	return unsafe.Pointer(uintptr(0)), 0, syscall.EAFNOSUPPORT
}

// anyToSockaddr converts a syscall.RawSockaddrAny to a syscall.Sockaddr
func anyToSockaddr(rsa *syscall.RawSockaddrAny) (syscall.Sockaddr, error) {
	switch rsa.Addr.Family {
	case syscall.AF_UNIX:
		pp := (*syscall.RawSockaddrUnix)(unsafe.Pointer(rsa))
		sa := new(syscall.SockaddrUnix)
		if pp.Path[0] == 0 {
			// "Abstract" Unix domain socket.
			// Rewrite leading NUL as @ for textual display.
			// (This is the standard convention.)
			// Not friendly to overwrite in place,
			// but the callers below don't care.
			pp.Path[0] = '@'
		}
		// Assume path ends at NUL.
		// This is not technically the Linux semantics for
		// abstract Unix domain sockets--they are supposed
		// to be uninterpreted fixed-size binary blobs--but
		// everyone uses this convention.
		n := 0
		for n < len(pp.Path) && pp.Path[n] != 0 {
			n++
		}
		bytes := (*[len(pp.Path)]byte)(unsafe.Pointer(&pp.Path[0]))[0:n]
		sa.Name = string(bytes)
		return sa, nil

	case syscall.AF_INET:
		pp := (*syscall.RawSockaddrInet4)(unsafe.Pointer(rsa))
		sa := new(syscall.SockaddrInet4)
		p := (*[2]byte)(unsafe.Pointer(&pp.Port))
		sa.Port = int(p[0])<<8 + int(p[1])
		for i := 0; i < len(sa.Addr); i++ {
			sa.Addr[i] = pp.Addr[i]
		}
		return sa, nil

	case syscall.AF_INET6:
		pp := (*syscall.RawSockaddrInet6)(unsafe.Pointer(rsa))
		sa := new(syscall.SockaddrInet6)
		p := (*[2]byte)(unsafe.Pointer(&pp.Port))
		sa.Port = int(p[0])<<8 + int(p[1])
		sa.ZoneId = pp.Scope_id
		for i := 0; i < len(sa.Addr); i++ {
			sa.Addr[i] = pp.Addr[i]
		}
		return sa, nil
	}
	return nil, syscall.EAFNOSUPPORT
}

// _Socklen is the type of a socket address length
type _Socklen uint32

// roundup rounds up the length to the nearest multiple of 4
func roundup(l *_Socklen) error {
	if *l%4 != 0 {
		if *l > (1<<31 - 1) {
			return syscall.EINVAL
		}
		*l = (*l + 3) & ^_Socklen(3)
	}
	return nil
}
