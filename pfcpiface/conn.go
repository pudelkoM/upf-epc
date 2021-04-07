// SPDX-License-Identifier: Apache-2.0
// Copyright(c) 2020 Intel Corporation

package main

import (
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/wmnsk/go-pfcp/message"
)

// PktBufSz : buffer size for incoming pkt
const (
	PktBufSz    = 1500
	PFCPPort    = "8805"
	MaxItems    = 10
	Timeout     = 1000 * time.Millisecond
	readTimeout = 25 * time.Second
)

// PFCPConn represents a PFCP connection
type PFCPConn struct {
	seqNum sequenceNumber
	mgr    *PFCPSessionMgr
}

type sequenceNumber struct {
	seq uint32
	mux sync.Mutex
}

func (c *PFCPConn) getSeqNum() uint32 {
	c.seqNum.mux.Lock()
	defer c.seqNum.mux.Unlock()
	c.seqNum.seq++
	return c.seqNum.seq
}

type rcvdPacket struct {
	Buf        [1500]byte
	Pkt_size   int
	Address    net.Addr
	SrcAddress string
}

type parsedPacket struct {
	Msg        *message.Message
	Address    net.Addr
	SrcAddress string
}

func pfcpifaceMainLoop(upf *upf, accessIP, coreIP, sourceIP, smfName string) {
	var pconn PFCPConn
	pconn.mgr = NewPFCPSessionMgr(100)

	log.Println("pfcpifaceMainLoop@" + upf.fqdnHost + " says hello!!!")

	cpConnectionStatus := make(chan bool)

	// Verify IP + Port binding
	laddr, err := net.ResolveUDPAddr("udp", sourceIP+":"+PFCPPort)
	if err != nil {
		log.Fatalln("Unable to resolve udp addr!", err)
		return
	}


	pfcpRcvdPktsChan := make(chan *rcvdPacket, 1000)
	pfcpParsedPktsChan := make(chan *parsedPacket, 1000)


	// Listen on the port
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatalln("Unable to bind to listening port!", err)
		return
	}
	go pconn.manageSmfConnection(upf, sourceIP, accessIP, smfName, conn, cpConnectionStatus)
	go pfcpPacketParsing(pfcpRcvdPktsChan, pfcpParsedPktsChan)
	go pfcpPacketProcessing(upf, conn, pfcpParsedPktsChan, cpConnectionStatus, accessIP, coreIP, &pconn)

	for {
		pkt := new(rcvdPacket)
		// blocking read
		n, addr, err := conn.ReadFrom(pkt.Buf[:1500])
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Timeout() {
				// do nothing for the time being
				log.Println(err)
				cpConnectionStatus <- false
                continue;
			}
			log.Fatalln("Read error:", err)
		}
		pkt.Pkt_size = n
		pkt.Address = addr
		// if sourceIP is not set, fetch it from the msg header
		if sourceIP == "0.0.0.0" {
			addrString := strings.Split(pkt.Address.String(), ":")
			sourceIP = getLocalIP(addrString[0]).String()
			log.Println("Source IP address is now: ", sourceIP)
		}
		pkt.SrcAddress = sourceIP
		pfcpRcvdPktsChan <- pkt
	}
}

// cleanup the pipeline
func cleanupSessions(upf *upf) {
	sendDeleteAllSessionsMsgtoUPF(upf)
}

func (pc *PFCPConn) manageSmfConnection(upf *upf, n4LocalIP string, n3ip string, n4Dst string, conn *net.UDPConn, cpConnectionStatus chan bool) {
	cpConnected := false

	initiatePfcpConnection := func() {
		log.Println("SPGWC/SMF hostname ", n4Dst)
		n4DstIP := getRemoteIP(n4Dst)
		log.Println("SPGWC/SMF address IP inside manageSmfConnection ", n4DstIP.String())
		// initiate request if we have control plane address available
		if n4DstIP.String() != "0.0.0.0" {
			pc.generateAssociationRequest(n4LocalIP, n3ip, n4DstIP.String(), conn)
		}
		// no worry. Looks like control plane is still not up
	}
	updateSmfStatus := func(msg bool) {
		log.Println("cpConnected : ", cpConnected, "msg ", msg)
		// events from main Loop
		if cpConnected && !msg {
			log.Println("CP disconnected ")
			cpConnected = false
            cleanupSessions(upf)
		} else if !cpConnected && msg {
			log.Println("CP Connected ")
			cpConnected = true
		} else {
			log.Println("cpConnected ", cpConnected, "msg - ", msg)
		}
	}

	if n4Dst != "" {
	    log.Println("initiate pfcp connection to smf - ", n4Dst)
	    initiatePfcpConnection()
    }

	connHelathTicker := time.NewTicker(5000 * time.Millisecond)
	pfcpResponseTicker := time.NewTicker(2000 * time.Millisecond)
	for {
		select {
		case msg := <-cpConnectionStatus:
			// events from main Loop
			updateSmfStatus(msg)
			if cpConnected {
				pfcpResponseTicker.Stop()
			}
		case <-connHelathTicker.C:
			if !cpConnected {
				log.Println("Retry pfcp connection setup ", n4Dst)
				initiatePfcpConnection()
			}
		case <-pfcpResponseTicker.C:
			log.Println("PFCP session setup timeout ")
			pfcpResponseTicker.Stop()
			// we will attempt new connection after next recheck
		}
	}
}

func pfcpPacketParsing(pfcpRcvdPktsChan chan *rcvdPacket, pfcpParsedPktsChan chan *parsedPacket) {
	for {
		select {
		case pkt := <-pfcpRcvdPktsChan:
			// use wmnsk lib to parse the pfcp message
			msg, err := message.Parse(pkt.Buf[:pkt.Pkt_size])
			if err != nil {
				log.Println("Ignoring undecodable message size ", pkt.Pkt_size)
				log.Println("Ignoring undecodable message: ", pkt.Buf[:pkt.Pkt_size], " error: ", err)
				return
			}

			pPkt := new(parsedPacket)
			pPkt.Msg = &msg
			pPkt.Address = pkt.Address
			pPkt.SrcAddress = pkt.SrcAddress
			pfcpParsedPktsChan <- pPkt
		}
	}
}

func pfcpPacketProcessing(upf *upf, conn *net.UDPConn, pfcpParsedPktsChan chan *parsedPacket, cpConnectionStatus chan bool, accessIP, coreIP string, pconn *PFCPConn) {
	cpConnected := false
	for {
		select {
		case pPkt := <-pfcpParsedPktsChan:

			msg := *pPkt.Msg
			// handle message
			var outgoingMessage []byte
			switch msg.MessageType() {
			case message.MsgTypeAssociationSetupRequest:
				outgoingMessage = pconn.handleAssociationSetupRequest(msg, pPkt.Address, pPkt.SrcAddress, accessIP, coreIP)
				if outgoingMessage != nil {
					// if we initiated connection, inform go routine
					cpConnectionStatus <- true
				}
			case message.MsgTypeAssociationSetupResponse:
				cpConnected = handleAssociationSetupResponse(msg, pPkt.Address, pPkt.SrcAddress, accessIP)
				cpConnectionStatus <- cpConnected
			case message.MsgTypePFDManagementRequest:
				outgoingMessage = pconn.handlePFDMgmtRequest(upf, msg, pPkt.Address, pPkt.SrcAddress)
			case message.MsgTypeSessionEstablishmentRequest:
				outgoingMessage = pconn.handleSessionEstablishmentRequest(upf, msg, pPkt.Address, pPkt.SrcAddress)
			case message.MsgTypeSessionModificationRequest:
				outgoingMessage = pconn.handleSessionModificationRequest(upf, msg, pPkt.Address, pPkt.SrcAddress)
			case message.MsgTypeHeartbeatRequest:
				outgoingMessage = handleHeartbeatRequest(msg, pPkt.Address)
			case message.MsgTypeSessionDeletionRequest:
				outgoingMessage = pconn.handleSessionDeletionRequest(upf, msg, pPkt.Address, pPkt.SrcAddress)
			case message.MsgTypeAssociationReleaseRequest:
				outgoingMessage = handleAssociationReleaseRequest(msg, pPkt.Address, pPkt.SrcAddress, accessIP)
				cleanupSessions(upf)
			default:
				log.Println("Message type: ", msg.MessageTypeName(), " is currently not supported")
				return
			}

			// send the response out
			if outgoingMessage != nil {
				if _, err := conn.WriteTo(outgoingMessage, pPkt.Address); err != nil {
					log.Fatalln("Unable to transmit association setup response", err)
				}
			}
		}
	}
}
