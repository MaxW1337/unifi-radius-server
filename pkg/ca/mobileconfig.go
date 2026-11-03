package ca

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"text/template"
)

// MobileConfigData contains all fields needed to generate an Apple .mobileconfig profile.
type MobileConfigData struct {
	PayloadUUID        string
	CertPayloadUUID    string
	WifiPayloadUUID    string
	RootCertPayloadUUID string
	ProfileName        string
	SSID               string
	ClientCertBase64   string
	ClientKeyBase64    string
	RootCertBase64     string
	Password           string
}

const mobileConfigTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array>
		<!-- Root CA Certificate -->
		<dict>
			<key>PayloadCertificateFileName</key>
			<string>UniFi-Root-CA.cer</string>
			<key>PayloadContent</key>
			<data>{{.RootCertBase64}}</data>
			<key>PayloadDescription</key>
			<string>Adds UniFi Root CA to Trusted Anchors</string>
			<key>PayloadDisplayName</key>
			<string>UniFi Root CA</string>
			<key>PayloadIdentifier</key>
			<string>com.unifi.radius.rootca.{{.RootCertPayloadUUID}}</string>
			<key>PayloadType</key>
			<string>ciscodce.certificate.root</string>
			<key>PayloadUUID</key>
			<string>{{.RootCertPayloadUUID}}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>

		<!-- Client Identity (Certificate & Key in PKCS#12) -->
		<dict>
			<key>Password</key>
			<string>{{.Password}}</string>
			<key>PayloadCertificateFileName</key>
			<string>client-identity.p12</string>
			<key>PayloadContent</key>
			<data>{{.ClientCertBase64}}</data>
			<key>PayloadDescription</key>
			<string>Provides client certificate for EAP-TLS 802.1X</string>
			<key>PayloadDisplayName</key>
			<string>Client Identity</string>
			<key>PayloadIdentifier</key>
			<string>com.unifi.radius.cert.{{.CertPayloadUUID}}</string>
			<key>PayloadType</key>
			<string>com.apple.security.pkcs12</string>
			<key>PayloadUUID</key>
			<string>{{.CertPayloadUUID}}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
		</dict>

		<!-- Wi-Fi 802.1X EAP-TLS Profile -->
		{{if .SSID}}
		<dict>
			<key>AutoJoin</key>
			<true/>
			<key>EncryptionType</key>
			<string>WPA2</string>
			<key>HIDDEN_NETWORK</key>
			<false/>
			<key>PayloadDescription</key>
			<string>Configures Wi-Fi with Enterprise EAP-TLS authentication</string>
			<key>PayloadDisplayName</key>
			<string>{{.SSID}} (802.1X)</string>
			<key>PayloadIdentifier</key>
			<string>com.unifi.radius.wifi.{{.WifiPayloadUUID}}</string>
			<key>PayloadType</key>
			<string>com.apple.wifi.managed</string>
			<key>PayloadUUID</key>
			<string>{{.WifiPayloadUUID}}</string>
			<key>PayloadVersion</key>
			<integer>1</integer>
			<key>SSID_STR</key>
			<string>{{.SSID}}</string>
			<key>EAPClientConfiguration</key>
			<dict>
				<key>AcceptEAPTypes</key>
				<array>
					<integer>13</integer> <!-- 13 = EAP-TLS -->
				</array>
				<key>PayloadCertificateAnchorUUID</key>
				<array>
					<string>{{.RootCertPayloadUUID}}</string>
				</array>
				<key>TLSTrustedServerNames</key>
				<array/>
			</dict>
		</dict>
		{{end}}
	</array>
	<key>PayloadDescription</key>
	<string>Configures 802.1X Enterprise Certificate Authentication for {{.ProfileName}}</string>
	<key>PayloadDisplayName</key>
	<string>{{.ProfileName}} Wi-Fi Profile</string>
	<key>PayloadIdentifier</key>
	<string>com.unifi.radius.profile.{{.PayloadUUID}}</string>
	<key>PayloadOrganization</key>
	<string>UniFi Network</string>
	<key>PayloadRemovalDisallowed</key>
	<false/>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>{{.PayloadUUID}}</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
`

func escapeXML(s string) string {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(s))
	return buf.String()
}

// GenerateAppleMobileConfig produces an Apple .mobileconfig XML profile for 1-click Wi-Fi setup.
func GenerateAppleMobileConfig(profileName, ssid string, pkcs12Data []byte, caCertPEM string, p12Password string) ([]byte, error) {
	if profileName == "" {
		profileName = "UniFi Enterprise"
	}

	caBlock, _ := pem.Decode([]byte(caCertPEM))
	if caBlock == nil {
		return nil, ErrInvalidPEM
	}

	data := MobileConfigData{
		PayloadUUID:         newUUID(),
		CertPayloadUUID:     newUUID(),
		WifiPayloadUUID:     newUUID(),
		RootCertPayloadUUID: newUUID(),
		ProfileName:         escapeXML(profileName),
		SSID:                escapeXML(ssid),
		ClientCertBase64:    base64.StdEncoding.EncodeToString(pkcs12Data),
		RootCertBase64:      base64.StdEncoding.EncodeToString(caBlock.Bytes),
		Password:            escapeXML(p12Password),
	}

	tmpl, err := template.New("mobileconfig").Parse(mobileConfigTemplate)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant RFC 4122
	return fmt.Sprintf("%08X-%04X-%04X-%04X-%012X",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
