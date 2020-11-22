//
// Very Simple SNIProxy with GO Language
// Code by Jioh L. Jung(ziozzang@gmail.com)
//
package main

import (
	"bufio"
	"container/list"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

var domains = []string{}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func on_disconnect(dst io.WriteCloser, conChk chan int) {
	// On Close-> Force Disconnect another pair of connection.
	dst.Close()
	conChk <- 1
}

func ioReflector(dst io.WriteCloser, src io.Reader, conChk chan int) {
	// Reflect IO stream to another.
	defer on_disconnect(dst, conChk)
	written, _ := io.Copy(dst, src)
	log.Printf("Written %d", written) //TODO: Update to Metric Info
	dst.Close()
	conChk <- 1
}

func handleSimpleHTTP(conn net.Conn) {
	headers := bufio.NewReader(conn)
	hostname := ""
	readLines := list.New()
	for {
		bytes, _, error := headers.ReadLine()
		if error != nil {
			conn.Close()
			return
		}
		line := string(bytes)
		log.Printf("%s", line)
		readLines.PushBack(line)
		if line == "" {
			// End of HTTP headers
			break
		}
		//Check Host Header.
		if strings.HasPrefix(line, "Host: ") {
			hostname = strings.TrimPrefix(line, "Host: ")
		}
	}

	backend, error := net.Dial("tcp", hostname+":80")
	if error != nil {
		log.Fatal("Couldn't connect to backend", error)
		conn.Close()
		return
	}

	for element := readLines.Front(); element != nil; element = element.Next() {
		line := element.Value.(string)
		backend.Write([]byte(line))
		backend.Write([]byte("\n"))
		log.Printf("> %s", line)
	}

	conChk := make(chan int)
	go ioReflector(backend, conn, conChk)
	go ioReflector(conn, backend, conChk)
}

func handleSimpleSNI(conn net.Conn) {
	// Simple SNI Protocol : SNI Handling Code from https://github.com/gpjt/stupid-proxy/
	firstByte := make([]byte, 1)
	_, error := conn.Read(firstByte)
	if error != nil {
		log.Printf("Couldn't read first byte :-(")
		return
	}
	if firstByte[0] != 0x16 {
		log.Printf("Not TLS :-(")
	}

	versionBytes := make([]byte, 2)
	_, error = conn.Read(versionBytes)
	if error != nil {
		log.Printf("Couldn't read version bytes :-(")
		return
	}
	if versionBytes[0] < 3 || (versionBytes[0] == 3 && versionBytes[1] < 1) {
		log.Printf("SSL < 3.1 so it's still not TLS v%d.%d", versionBytes[0], versionBytes[1])
		return
	}

	restLengthBytes := make([]byte, 2)
	_, error = conn.Read(restLengthBytes)
	if error != nil {
		log.Printf("Couldn't read restLength bytes :-(")
		return
	}
	restLength := (int(restLengthBytes[0]) << 8) + int(restLengthBytes[1])

	rest := make([]byte, restLength)
	_, error = conn.Read(rest)
	if error != nil {
		log.Printf("Couldn't read rest of bytes")
		return
	}

	current := 0

	handshakeType := rest[0]
	current += 1
	if handshakeType != 0x1 {
		log.Printf("Not a ClientHello")
		return
	}

	// Skip over another length
	current += 3
	// Skip over protocolversion
	current += 2
	// Skip over random number
	current += 4 + 28
	// Skip over session ID
	sessionIDLength := int(rest[current])
	current += 1
	current += sessionIDLength

	cipherSuiteLength := (int(rest[current]) << 8) + int(rest[current+1])
	current += 2
	current += cipherSuiteLength

	compressionMethodLength := int(rest[current])
	current += 1
	current += compressionMethodLength

	if current > restLength {
		log.Println("no extensions")
		return
	}

	// Skip over extensionsLength
	// extensionsLength := (int(rest[current]) << 8) + int(rest[current + 1])
	current += 2

	hostname := ""
	for current < restLength && hostname == "" {
		extensionType := (int(rest[current]) << 8) + int(rest[current+1])
		current += 2

		extensionDataLength := (int(rest[current]) << 8) + int(rest[current+1])
		current += 2

		if extensionType == 0 {
			// Skip over number of names as we're assuming there's just one
			current += 2

			nameType := rest[current]
			current += 1
			if nameType != 0 {
				log.Printf("Not a hostname")
				return
			}
			nameLen := (int(rest[current]) << 8) + int(rest[current+1])
			current += 2
			hostname = string(rest[current : current+nameLen])
		}

		current += extensionDataLength
	}

	if hostname == "" {
		log.Printf("No hostname")
		return
	}

	backend, error := net.Dial("tcp", hostname+":443")
	if error != nil {
		log.Fatal("Couldn't connect to backend", error)
		backend.Close()
		return
	}

	backend.Write(firstByte)
	backend.Write(versionBytes)
	backend.Write(restLengthBytes)
	backend.Write(rest)

	conChk := make(chan int)
	go ioReflector(backend, conn, conChk)
	go ioReflector(conn, backend, conChk)
}

func deferListen(term chan int) {
}

func startListenTCP(ip string, port int, handle func(net.Conn), term chan int) {
	defer deferListen(term)

	listener, error := net.Listen("tcp", ip+":"+strconv.Itoa(port))
	if error != nil {
		log.Printf("Couldn't start listening", error)
		return
	}
	log.Printf("Started proxy on %s:%d -- listening", ip, port)
	for {
		connection, error := listener.Accept()
		if error != nil {
			log.Printf("Accept error", error)
			return
		}
		log.Printf("From: %s", connection.RemoteAddr().String())
		go handle(connection)
	}
}

func startListenDNS(ip string, port int, handle func(dns.ResponseWriter, *dns.Msg), term chan int) {

	dns.HandleFunc(".", handle)

	// start server
	server := &dns.Server{Addr: ":" + strconv.Itoa(port), Net: "udp"}
	log.Printf("Started DNS on %s:%d -- listening", "0.0.0.0", port)
	err := server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}

func parseQuery(m *dns.Msg, ip string) {
	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeA:
			for i := 1; i <= strings.Count(q.Name, "."); i++ {
				tmpSplitList := strings.SplitN(q.Name, ".", i)
				if stringInSlice(tmpSplitList[len(tmpSplitList)-1], domains) {
					rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip))
					if err == nil {
						log.Printf("Routing Traffic for %s\n", q.Name)
						m.Answer = append(m.Answer, rr)
						return
					}
				}
			}
		}
		log.Printf("Bypassing Traffic for %s\n", q.Name)
		upstreamip := flag.Lookup("upstreamdns").Value.(flag.Getter).Get().(string)
		c := new(dns.Client)
		m1 := new(dns.Msg)
		m1.Id = dns.Id()
		m1.RecursionDesired = true
		m1.Question = make([]dns.Question, 1)
		m1.Question[0] = q

		in, _, err := c.Exchange(m1, fmt.Sprintf("%s:53", upstreamip))
		if err != nil {
			println("error")
		}
		m.Answer = append(m.Answer, in.Answer...)
	}

}

func handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	ip := flag.Lookup("publicip").Value.(flag.Getter).Get().(string)

	switch r.Opcode {
	case dns.OpcodeQuery:
		parseQuery(m, ip)
	}

	w.WriteMsg(m)
}

func updateDomainList(path *string) {
	file, err := os.Open(*path)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line[0] == '.' {
			line = line[1:]
		}
		if line[len(line)-1] != '.' {
			line += "."
		}
		domains = append(domains, line)
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
}

func main() {
	bindIP := flag.String("bindip", "0.0.0.0", "Bind to a Specific IP Address. Doesn't apply to DNS Server. DNS Server always listens on 0.0.0.0")
	upstreamDNS := flag.String("upstreamdns", "1.1.1.1", "Upstream DNS IP")
	domainListPath := flag.String("domainlist", "", "domain list path. eg: /tmp/domainlist.log")
	publicIP := flag.String("publicip", "", "Public IP of this server, reply address of DNS queries")
	flag.Parse()

	if *domainListPath == "" || *publicIP == "" || *upstreamDNS == "" {
		println("-domainListPath and -publicIP must be set. exitting...")
		os.Exit(-1)
	}

	updateDomainList(domainListPath)
	for i := 0; i < len(domains); i++ {
	}

	tchan := make(chan int)
	go startListenTCP(*bindIP, 80, handleSimpleHTTP, tchan)
	go startListenTCP(*bindIP, 443, handleSimpleSNI, tchan)
	go startListenDNS(*bindIP, 53, handleDNS, tchan)
	<-tchan

}
