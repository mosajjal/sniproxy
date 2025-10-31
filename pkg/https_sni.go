/* {{{ Copyright 2017 Paul Tagliamonte
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. }}} */

package sniproxy

import (
	"fmt"
	"regexp"
)

var tlsHeaderLength = 5

// GetHostname extracts the Server Name Indication (SNI) from a TLS Client Hello packet.
// This function takes raw TLS handshake data and returns the hostname requested by the client.
// It returns an error if the data doesn't contain a valid TLS Client Hello or SNI extension.
func GetHostname(data []byte) (string, error) {
	if len(data) == 0 || data[0] != 0x16 {
		return "", fmt.Errorf("Doesn't look like a TLS Client Hello")
	}

	extensions, err := getExtensionBlock(data)
	if err != nil {
		return "", err
	}
	sn, err := getSNBlock(extensions)
	if err != nil {
		return "", err
	}
	sni, err := getSNIBlock(sn)
	if err != nil {
		return "", err
	}
	return string(sni), nil
}

// lengthFromData extracts a 16-bit length value from two consecutive bytes at the given index.
// It interprets the bytes as a big-endian unsigned integer.
func lengthFromData(data []byte, index int) int {
	b1 := int(data[index])
	b2 := int(data[index+1])

	return (b1 << 8) + b2
}

// getSNIBlock parses a Server Name TLS Extension block and extracts the SNI (Server Name Indication) payload.
// It returns the raw SNI bytes or an error if the SNI extension is not found.
func getSNIBlock(data []byte) ([]byte, error) {
	index := 0

	for {
		if index >= len(data) {
			break
		}
		length := lengthFromData(data, index)
		endIndex := index + 2 + length
		if data[index+2] == 0x00 { /* SNI */
			sni := data[index+3:]
			sniLength := lengthFromData(sni, 0)
			return sni[2 : sniLength+2], nil
		}
		index = endIndex
	}
	return []byte{}, fmt.Errorf(
		"Finished parsing the SN block without finding an SNI",
	)
}

// getSNBlock parses the TLS Extensions data block to find and return the Server Name (SN) extension block.
// It returns an error if the SN block is not found or the data is malformed.
func getSNBlock(data []byte) ([]byte, error) {
	index := 0

	if len(data) < 2 {
		return []byte{}, fmt.Errorf("Not enough bytes to be an SN block")
	}

	extensionLength := lengthFromData(data, index)
	if extensionLength+2 > len(data) {
		return []byte{}, fmt.Errorf("Extension looks bonkers")
	}
	data = data[2 : extensionLength+2]

	for {
		if index+4 >= len(data) {
			break
		}
		length := lengthFromData(data, index+2)
		endIndex := index + 4 + length
		if data[index] == 0x00 && data[index+1] == 0x00 {
			return data[index+4 : endIndex], nil
		}

		index = endIndex
	}

	return []byte{}, fmt.Errorf(
		"Finished parsing the Extension block without finding an SN block",
	)
}

// getExtensionBlock extracts all Extensions from a raw TLS Client Hello message.
// It parses the TLS handshake structure to locate and return the extensions section.
func getExtensionBlock(data []byte) ([]byte, error) {
	/*   data[0]           - content type
	 *   data[1], data[2]  - major/minor version
	 *   data[3], data[4]  - total length
	 *   data[...38+5]     - start of SessionID (length bit)
	 *   data[38+5]        - length of SessionID
	 */
	var index = tlsHeaderLength + 38

	if len(data) <= index+1 {
		return []byte{}, fmt.Errorf("Not enough bits to be a Client Hello")
	}

	/* Index is at SessionID Length bit */
	if newIndex := index + 1 + int(data[index]); (newIndex + 2) < len(data) {
		index = newIndex
	} else {
		return []byte{}, fmt.Errorf("Not enough bytes for the SessionID")
	}

	/* Index is at Cipher List Length bits */
	if newIndex := (index + 2 + lengthFromData(data, index)); (newIndex + 1) < len(data) {
		index = newIndex
	} else {
		return []byte{}, fmt.Errorf("Not enough bytes for the Cipher List")
	}

	/* Index is now at the compression length bit */
	if newIndex := index + 1 + int(data[index]); newIndex < len(data) {
		index = newIndex
	} else {
		return []byte{}, fmt.Errorf("Not enough bytes for the compression length")
	}

	/* Now we're at the Extension start */
	if len(data[index:]) == 0 {
		return nil, fmt.Errorf("No extensions")
	}
	return data[index:], nil
}

// isValidFQDN validates if the given hostname is a valid FQDN
func isValidFQDN(hostname string) bool {
	// Regular expression to match a valid FQDN
	var fqdnRegex = regexp.MustCompile(`^(?i:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,})$`)
	return fqdnRegex.MatchString(hostname)
}

// vim: foldmethod=marker
