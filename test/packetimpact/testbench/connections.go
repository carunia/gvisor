// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package testbench has utilities to send and receive packets and also command
// the DUT to run POSIX functions.
package testbench

import (
	"flag"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mohae/deepcopy"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/seqnum"
)

var localIPv4 = flag.String("local_ipv4", "", "local IPv4 address for test packets")
var remoteIPv4 = flag.String("remote_ipv4", "", "remote IPv4 address for test packets")
var localMAC = flag.String("local_mac", "", "local mac address for test packets")
var remoteMAC = flag.String("remote_mac", "", "remote mac address for test packets")

// pickPort makes a new socket and returns the socket FD and port. The caller
// must close the FD when done with the port if there is no error.
func pickPort() (int, uint16, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		return -1, 0, err
	}
	var sa unix.SockaddrInet4
	copy(sa.Addr[0:4], net.ParseIP(*localIPv4).To4())
	if err := unix.Bind(fd, &sa); err != nil {
		unix.Close(fd)
		return -1, 0, err
	}
	newSockAddr, err := unix.Getsockname(fd)
	if err != nil {
		unix.Close(fd)
		return -1, 0, err
	}
	newSockAddrInet4, ok := newSockAddr.(*unix.SockaddrInet4)
	if !ok {
		unix.Close(fd)
		return -1, 0, fmt.Errorf("can't cast Getsockname result to SockaddrInet4")
	}
	return fd, uint16(newSockAddrInet4.Port), nil
}

// layerState stores the state of a layer of a connection.
type layerState interface {
	// Outgoing returns an outgoing layer to be sent in a frame.
	Outgoing() Layer

	// match matches a received layer against the expected incoming frame, with
	// override overriding any expectations in the layerState.
	match(override, received Layer) bool

	// sent updates the layerState based on a frame that is sent. The input is a
	// Layer with all prev and next pointers populated so that the entire frame as
	// it was sent is available.
	sent(Layer)

	// received updates the layerState based on a frame that is receieved. The
	// input is a Layer with all prev and next pointers populated so that the
	// entire frame as it was receieved is available.
	received(Layer)

	// Close cleans up any resources held.
	Close() error
}

// matchWithOverride merges override into a copy of toMatch and then compares it
// against other. It returns true if everything succeeds.
func matchWithOverride(toMatch, override, other Layer) bool {
	expected := deepcopy.Copy(toMatch).(Layer)
	if expected.merge(override) != nil {
		return false
	}
	return expected.match(other)
}

// EtherState maintains state about an Ethernet connection.
type EtherState struct {
	outgoing, incoming Ether
}

// NewEtherState creates a new EtherState.
func NewEtherState(outgoing, incoming Ether) (*EtherState, error) {
	lMAC, err := tcpip.ParseMACAddress(*localMAC)
	if err != nil {
		return nil, err
	}

	rMAC, err := tcpip.ParseMACAddress(*remoteMAC)
	if err != nil {
		return nil, err
	}
	s := EtherState{
		outgoing: Ether{SrcAddr: &lMAC, DstAddr: &rMAC},
		incoming: Ether{SrcAddr: &rMAC, DstAddr: &lMAC},
	}
	if err := s.outgoing.merge(&outgoing); err != nil {
		return nil, err
	}
	if err := s.incoming.merge(&incoming); err != nil {
		return nil, err
	}
	return &s, nil
}

// Outgoing returns an outgoing layer to be sent in a frame.
func (s *EtherState) Outgoing() Layer {
	return &s.outgoing
}

// match matches a layer against the expected incoming frame.
func (s *EtherState) match(override, received Layer) bool {
	return matchWithOverride(&s.incoming, override, received)
}

func (s *EtherState) sent(Layer) {
	// Nothing to do.
}

func (s *EtherState) received(Layer) {
	// Nothing to do.
}

// Close cleans up any resources held.
func (s *EtherState) Close() error {
	return nil
}

// IPv4State maintains state about an IPv4 connection.
type IPv4State struct {
	outgoing, incoming IPv4
}

// NewIPv4State creates a new IPv4State.
func NewIPv4State(outgoing, incoming IPv4) (*IPv4State, error) {
	lIP := tcpip.Address(net.ParseIP(*localIPv4).To4())
	rIP := tcpip.Address(net.ParseIP(*remoteIPv4).To4())
	s := IPv4State{
		outgoing: IPv4{SrcAddr: &lIP, DstAddr: &rIP},
		incoming: IPv4{SrcAddr: &rIP, DstAddr: &lIP},
	}
	if err := s.outgoing.merge(&outgoing); err != nil {
		return nil, err
	}
	if err := s.incoming.merge(&incoming); err != nil {
		return nil, err
	}
	return &s, nil
}

// Outgoing returns an outgoing layer to be sent in a frame.
func (s *IPv4State) Outgoing() Layer {
	return &s.outgoing
}

// match matches a layer against the expected incoming frame.
func (s *IPv4State) match(override, received Layer) bool {
	return matchWithOverride(&s.incoming, override, received)
}

func (s *IPv4State) sent(Layer) {
	// Nothing to do.
}

func (s *IPv4State) received(Layer) {
	// Nothing to do.
}

// Close cleans up any resources held.
func (s *IPv4State) Close() error {
	return nil
}

// TCPState maintains state about a TCP connection.
type TCPState struct {
	outgoing, incoming        TCP
	LocalSeqNum, RemoteSeqNum *seqnum.Value
	SynAck                    *TCP
	portPickerFD              int
}

// SeqNumValue is a helper routine that allocates a new seqnum.Value value to
// store v and returns a pointer to it.
func SeqNumValue(v seqnum.Value) *seqnum.Value {
	return &v
}

// NewTCPState creates a new TCPState.
func NewTCPState(outgoing, incoming TCP) (*TCPState, error) {
	portPickerFD, localPort, err := pickPort()
	if err != nil {
		return nil, err
	}
	s := TCPState{
		outgoing:     TCP{SrcPort: &localPort},
		incoming:     TCP{DstPort: &localPort},
		LocalSeqNum:  SeqNumValue(seqnum.Value(rand.Uint32())),
		portPickerFD: portPickerFD,
	}
	if err := s.outgoing.merge(&outgoing); err != nil {
		return nil, err
	}
	if err := s.incoming.merge(&incoming); err != nil {
		return nil, err
	}
	return &s, nil
}

// Outgoing returns an outgoing layer to be sent in a frame.
func (s *TCPState) Outgoing() Layer {
	newOutgoing := deepcopy.Copy(s.outgoing).(TCP)
	if s.LocalSeqNum != nil {
		newOutgoing.SeqNum = Uint32(uint32(*s.LocalSeqNum))
	}
	if s.RemoteSeqNum != nil {
		newOutgoing.AckNum = Uint32(uint32(*s.RemoteSeqNum))
	}
	return &newOutgoing
}

// match matches a layer against the expected incoming frame.
func (s *TCPState) match(override, received Layer) bool {
	tcpOverride, ok := override.(*TCP)
	if !ok {
		return false
	}
	tcpReceived, ok := received.(*TCP)
	if !ok {
		return false
	}
	if tcpOverride.SeqNum == nil && s.RemoteSeqNum != nil {
		// The caller didn't specify a SeqNum so we'll expect the calculated one.
		tcpOverride.SeqNum = Uint32(uint32(*s.RemoteSeqNum))
	}
	if tcpOverride.AckNum == nil && s.LocalSeqNum != nil && (*tcpReceived.Flags&header.TCPFlagAck) != 0 {
		// The caller didn't specify an AckNum so we'll expect the calculated one,
		// but only if the ACK flag is set because the AckNum is not valid in a
		// header if ACK is not set.
		tcpOverride.AckNum = Uint32(uint32(*s.LocalSeqNum))
	}
	return matchWithOverride(&s.incoming, override, received)
}

func (s *TCPState) sent(l Layer) {
	tcp, ok := l.(*TCP)
	if !ok {
		panic("can't update TCPState with non-TCP Layer")
	}
	for current := tcp.next(); current != nil; current = current.next() {
		s.LocalSeqNum.UpdateForward(seqnum.Size(current.length()))
	}
	if tcp.Flags != nil && *tcp.Flags&(header.TCPFlagSyn|header.TCPFlagFin) != 0 {
		s.LocalSeqNum.UpdateForward(1)
	}
}

func (s *TCPState) received(l Layer) {
	tcp, ok := l.(*TCP)
	if !ok {
		panic("can't update TCPState with non-TCP Layer")
	}
	s.RemoteSeqNum = SeqNumValue(seqnum.Value(*tcp.SeqNum))
	if *tcp.Flags&(header.TCPFlagSyn|header.TCPFlagFin) != 0 {
		s.RemoteSeqNum.UpdateForward(1)
	}
	for current := tcp.next(); current != nil; current = current.next() {
		s.RemoteSeqNum.UpdateForward(seqnum.Size(current.length()))
	}
}

// Close the port associated with this connection.
func (s *TCPState) Close() error {
	if err := unix.Close(s.portPickerFD); err != nil {
		return err
	}
	s.portPickerFD = -1
	return nil
}

// UDPState maintains state about a UDP connection.
type UDPState struct {
	outgoing, incoming UDP
	portPickerFD       int
}

// NewUDPState creates a new UDPState.
func NewUDPState(outgoing, incoming UDP) (*UDPState, error) {
	portPickerFD, localPort, err := pickPort()
	if err != nil {
		return nil, err
	}
	s := UDPState{
		outgoing:     UDP{SrcPort: &localPort},
		incoming:     UDP{DstPort: &localPort},
		portPickerFD: portPickerFD,
	}
	if err := s.outgoing.merge(&outgoing); err != nil {
		return nil, err
	}
	if err := s.incoming.merge(&incoming); err != nil {
		return nil, err
	}
	return &s, nil
}

// Outgoing returns an outgoing layer to be sent in a frame.
func (s *UDPState) Outgoing() Layer {
	return &s.outgoing
}

// match matches a layer against the expected incoming frame.
func (s *UDPState) match(override, received Layer) bool {
	return matchWithOverride(&s.incoming, override, received)
}

func (s *UDPState) sent(l Layer) {
	// Nothing to do.
}

func (s *UDPState) received(l Layer) {
	// Nothing to do.
}

// Close the port associated with this connection.
func (s *UDPState) Close() error {
	if err := unix.Close(s.portPickerFD); err != nil {
		return err
	}
	s.portPickerFD = -1
	return nil
}

// Connection holds a collection of layer states for maintaining a connection
// along with sockets for sniffer and injecting packets.
type Connection struct {
	layerStates []layerState
	injector    Injector
	sniffer     Sniffer
	t           *testing.T
}

// match tries to match each Layer in received against the incoming filter. If
// received is longer than layerStates then that may still count as a match. The
// reverse is never a match. override overrides the default matchers for each
// Layer.
func (conn *Connection) match(override, received Layers) bool {
	if len(received) < len(conn.layerStates) {
		return false
	}
	for i, s := range conn.layerStates {
		if i < len(override) && !s.match(override[i], received[i]) {
			return false
		}
		if i >= len(override) && !s.match(nil, received[i]) {
			return false
		}
	}
	return true
}

// Close cleans up any resources held.
func (conn *Connection) Close() {
	conn.sniffer.Close()
	conn.injector.Close()
	for _, s := range conn.layerStates {
		if err := s.Close(); err != nil {
			conn.t.Errorf("unable to close %v: %s", s, err)
		}
	}
}

// CreateFrame builds a frame for the connection with layer overriding defaults
// of the innermost layer and additionalLayers added after it.
func (conn *Connection) CreateFrame(layer Layer, additionalLayers ...Layer) Layers {
	var layersToSend Layers
	for _, s := range conn.layerStates {
		layersToSend = append(layersToSend, s.Outgoing())
	}
	if err := layersToSend[len(layersToSend)-1].merge(layer); err != nil {
		conn.t.Fatalf("can't merge %+v into %+v: %s", layer, layersToSend[len(layersToSend)-1], err)
	}
	layersToSend = append(layersToSend, additionalLayers...)
	return layersToSend
}

// SendFrame sends a frame on the wire and updates the state of all layers.
func (conn *Connection) SendFrame(frame Layers) {
	outBytes, err := frame.toBytes()
	if err != nil {
		conn.t.Fatalf("can't build outgoing TCP packet: %s", err)
	}
	conn.injector.Send(outBytes)

	// frame might have nil values where the caller wanted to use default values.
	// sentFrame will have no nil values in it because it comes from parsing the
	// bytes that were actually sent.
	sentFrame := Parse(ParseEther, outBytes)
	// Update the state of each layer based on what was sent.
	for i, s := range conn.layerStates {
		s.sent(sentFrame[i])
	}
}

// Send a packet with reasonable defaults. Potentially override the final layer
// in the connection with the provided layer and add additionLayers.
func (conn *Connection) Send(layer Layer, additionalLayers ...Layer) {
	conn.SendFrame(conn.CreateFrame(layer, additionalLayers...))
}

// recvFrame gets the next successfully parsed frame (of type Layers) within the
// timeout provided. If no parsable frame arrives before the timeout, it returns
// nil.
func (conn *Connection) recvFrame(timeout time.Duration) Layers {
	if timeout <= 0 {
		return nil
	}
	b := conn.sniffer.Recv(timeout)
	if b == nil {
		return nil
	}
	return Parse(ParseEther, b)
}

// Expect a frame with the final layerStates layer matching the provided Layer
// within the timeout specified. If it doesn't arrive in time, it returns nil.
func (conn *Connection) Expect(layer Layer, timeout time.Duration) (Layer, error) {
	// Make a frame that will ignore all but the final layer.
	layers := make([]Layer, len(conn.layerStates))
	layers[len(layers)-1] = layer

	gotFrame, err := conn.ExpectFrame(layers, timeout)
	if err != nil {
		return nil, err
	}
	if len(conn.layerStates)-1 < len(gotFrame) {
		return gotFrame[len(conn.layerStates)-1], nil
	}
	panic("the received frame should be at least as long as the expected layers")
}

// ExpectFrame expects a frame that matches the provided Layers within the
// timeout specified. If it doesn't arrive in time, it returns nil.
func (conn *Connection) ExpectFrame(layers Layers, timeout time.Duration) (Layers, error) {
	deadline := time.Now().Add(timeout)
	var allLayers []string
	for {
		var gotLayers Layers
		if timeout = time.Until(deadline); timeout > 0 {
			gotLayers = conn.recvFrame(timeout)
		}
		if gotLayers == nil {
			return nil, fmt.Errorf("got %d packets:\n%s", len(allLayers), strings.Join(allLayers, "\n"))
		}
		if conn.match(layers, gotLayers) {
			for i, s := range conn.layerStates {
				s.received(gotLayers[i])
			}
			return gotLayers, nil
		}
		allLayers = append(allLayers, fmt.Sprintf("%v", gotLayers))
	}
}

// TCPIPv4 maintains the state for all the layers in a TCP/IPv4 connection.
type TCPIPv4 Connection

// NewTCPIPv4 creates a new TCPIPv4 connection with reasonable defaults.
func NewTCPIPv4(t *testing.T, outgoingTCP, incomingTCP TCP) TCPIPv4 {
	etherState, err := NewEtherState(Ether{}, Ether{})
	if err != nil {
		t.Fatalf("can't make EtherState: %s", err)
	}
	ipv4State, err := NewIPv4State(IPv4{}, IPv4{})
	if err != nil {
		t.Fatalf("can't make IPv4State: %s", err)
	}
	tcpState, err := NewTCPState(outgoingTCP, incomingTCP)
	if err != nil {
		t.Fatalf("can't make TCPState: %s", err)
	}
	injector, err := NewInjector(t)
	if err != nil {
		t.Fatalf("can't make injector: %s", err)
	}
	sniffer, err := NewSniffer(t)
	if err != nil {
		t.Fatalf("can't make sniffer: %s", err)
	}

	return TCPIPv4{
		layerStates: []layerState{etherState, ipv4State, tcpState},
		injector:    injector,
		sniffer:     sniffer,
		t:           t,
	}
}

// Handshake performs a TCP 3-way handshake. The input Connection should have a
// final TCP Layer.
func (conn *TCPIPv4) Handshake() {
	// Send the SYN.
	conn.Send(TCP{Flags: Uint8(header.TCPFlagSyn)})

	// Wait for the SYN-ACK.
	synAck, err := conn.Expect(TCP{Flags: Uint8(header.TCPFlagSyn | header.TCPFlagAck)}, time.Second)
	if synAck == nil {
		conn.t.Fatalf("didn't get synack during handshake: %s", err)
	}
	conn.layerStates[len(conn.layerStates)-1].(*TCPState).SynAck = synAck

	// Send an ACK.
	conn.Send(TCP{Flags: Uint8(header.TCPFlagAck)})
}

// ExpectData is a convenient method that expects a Layer and the Layer after
// it. If it doens't arrive in time, it returns nil.
func (conn *TCPIPv4) ExpectData(tcp *TCP, payload *Payload, timeout time.Duration) (Layers, error) {
	expected := make([]Layer, len(conn.layerStates))
	expected[len(expected)-1] = tcp
	if payload != nil {
		expected = append(expected, payload)
	}
	return (*Connection)(conn).ExpectFrame(expected, timeout)
}

// Send a packet with reasonable defaults. Potentially override the TCP layer in
// the connection with the provided layer and add additionLayers.
func (conn *TCPIPv4) Send(tcp TCP, additionalLayers ...Layer) {
	(*Connection)(conn).Send(&tcp, additionalLayers...)
}

// Close to clean up any resources held.
func (conn *TCPIPv4) Close() {
	(*Connection)(conn).Close()
}

// Expect a frame with the TCP layer matching the provided TCP within the
// timeout specified. If it doesn't arrive in time, it returns nil.
func (conn *TCPIPv4) Expect(tcp TCP, timeout time.Duration) (*TCP, error) {
	layer, err := (*Connection)(conn).Expect(&tcp, timeout)
	if layer == nil {
		return nil, err
	}
	gotTCP, ok := layer.(*TCP)
	if !ok {
		conn.t.Fatalf("expected %s to be TCP", layer)
	}
	return gotTCP, err
}

// State returns the stored TCPState of the TCPIPv4 Connection.
func (conn *TCPIPv4) State() *TCPState {
	state, ok := conn.layerStates[len(conn.layerStates)-1].(*TCPState)
	if !ok {
		conn.t.Fatalf("expected final state of %v to be TCPState", conn.layerStates)
	}
	return state
}

// NewUDPIPv4 creates a new UDPIPv4 connection with reasonable defaults.
func NewUDPIPv4(t *testing.T, outgoingUDP, incomingUDP UDP) Connection {
	etherState, err := NewEtherState(Ether{}, Ether{})
	if err != nil {
		t.Fatalf("can't make EtherState: %s", err)
	}
	ipv4State, err := NewIPv4State(IPv4{}, IPv4{})
	if err != nil {
		t.Fatalf("can't make IPv4State: %s", err)
	}
	tcpState, err := NewUDPState(outgoingUDP, incomingUDP)
	if err != nil {
		t.Fatalf("can't make UDPState: %s", err)
	}
	injector, err := NewInjector(t)
	if err != nil {
		t.Fatalf("can't make injector: %s", err)
	}
	sniffer, err := NewSniffer(t)
	if err != nil {
		t.Fatalf("can't make sniffer: %s", err)
	}

	return Connection{
		layerStates: []layerState{etherState, ipv4State, tcpState},
		injector:    injector,
		sniffer:     sniffer,
		t:           t,
	}
}
