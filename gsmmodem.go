package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"go.bug.st/serial"
)

type Modem interface {
	Init() error
	SendMessage(phoneNr string, message string) error
	Close()
}

type GsmModem struct {
	simPin string
	port   serial.Port
}

func NewGsmModem(simPin string, device string) (*GsmModem, error) {
	port, err := setupPort(device, 115200, 20)
	if err != nil {
		return nil, fmt.Errorf("Unable to open port: %s: %v", device, err)
	}

	res := GsmModem{
		simPin: simPin,
		port:   port,
	}

	return &res, nil
}

func setupPort(device string, baudRate int, timeOutInSeconds int) (serial.Port, error) {
	mode := &serial.Mode{
		BaudRate: baudRate,
	}

	port, err := serial.Open(device, mode)
	if err != nil {
		return nil, err
	}

	err = port.SetReadTimeout(time.Duration(timeOutInSeconds) * time.Second)
	if err != nil {
		port.Close()
		return nil, err
	}

	return port, nil
}

func truncate(s string, maxChars int) string {
	if utf8.RuneCountInString(s) > maxChars {
		return string([]rune(s)[:maxChars])
	}
	return s
}

func transformMessageText(msg string) string {
	var b strings.Builder

	// truncate to at most 160 runes
	msg = truncate(msg, 160)

	// Encode the german Umlauts as the values found through
	// experimentation which are displayed correctly on my
	// mobile phone
	for _, c := range msg {
		switch c {
		case 'ä':
			b.WriteByte(0x84)
		case 'ü':
			b.WriteByte(0x81)
		case 'ö':
			b.WriteByte(0x94)
		case 'Ä':
			b.WriteByte(0x8E)
		case 'Ü':
			b.WriteByte(0x9a)
		case 'Ö':
			b.WriteByte(0x99)
		case 'ß':
			b.WriteByte(0xe1)
		default:
			b.WriteRune(c)
		}
	}

	resBytes := []byte(b.String())

	// The string has probably been changed into a byte vector which is not properly
	// UTF-8 encoded, so we can not call truncate again
	return string(resBytes[:min(160, len(resBytes))])
}

func (g *GsmModem) sendModemCommand(command string) error {
	bytesToSend := []byte(command)
	bytesToSend = append(bytesToSend, '\r')
	bytesWritten, err := io.Copy(g.port, bytes.NewReader(bytesToSend))
	if err != nil {
		return err
	}
	// ToDo: This may not be neccessary if err == nil
	if bytesWritten != int64(len(bytesToSend)) {
		return fmt.Errorf("Write error")
	}

	return nil
}

func (g *GsmModem) readNonEmptyLine() (string, error) {
	var err error
	res := ""
	reader := bufio.NewReader(g.port)

	for res == "" {
		res, err = reader.ReadString('\n')
		if err != nil {
			return "", err
		}

		res = strings.TrimSpace(res)
	}

	return res, nil
}

func (g *GsmModem) skipBytes(toSkip int) error {
	oneByteBuffer := []byte{0x00}

	for i := 0; i < toSkip; i++ {
		n, err := g.port.Read(oneByteBuffer)
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("Unable to read byte to skip")
		}
	}

	return nil
}

func (g *GsmModem) EchoOff() error {
	err := g.sendModemCommand("ATE0")
	if err != nil {
		return err
	}

	lastTwoBytes := []byte{0x00, 0x00}
	oneByteBuffer := []byte{0x00}
	// I assume that this command can never fail, so we will read OK
	// eventually, after reading our potentially echoed command
	for {
		n, err := g.port.Read(oneByteBuffer)
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("Unexpexted data length: %d", n)
		}
		lastTwoBytes[0] = lastTwoBytes[1]
		lastTwoBytes[1] = oneByteBuffer[0]

		if string(lastTwoBytes) == "OK" {
			break
		}
	}

	// We have found OK. OK is followed by 0x0d,0x0a on my modem
	err = g.skipBytes(2)
	if err != nil {
		return err
	}

	return nil
}

func (g *GsmModem) IsSimReady() (bool, error) {
	err := g.sendModemCommand("AT+CPIN?")
	if err != nil {
		return false, err
	}

	answer, err := g.readNonEmptyLine()
	if err != nil {
		return false, err
	}
	return (answer == "+CPIN: READY"), nil
}

func (g *GsmModem) SendMessage(phoneNr string, message string) error {
	err := g.sendModemCommand(fmt.Sprintf("AT+CMGS=\"+%s\"", phoneNr))
	if err != nil {
		return err
	}

	oneByteBuffer := []byte{0x00}
	for {
		bytesRead, err := g.port.Read(oneByteBuffer)
		if err != nil {
			return err
		}
		if bytesRead != 1 {
			return fmt.Errorf("Unexpected data while waiting for message start")
		}

		if oneByteBuffer[0] == '>' {
			break
		}
	}

	bytesToSend := []byte(message)
	bytesToSend = append(bytesToSend, 0x1A)
	bytesWritten, err := io.Copy(g.port, bytes.NewReader(bytesToSend))
	if err != nil {
		return err
	}
	// ToDo: This may not be neccessary if err == nil
	if bytesWritten != int64(len(bytesToSend)) {
		return fmt.Errorf("Write error")
	}

	answer, err := g.readNonEmptyLine()
	if err != nil {
		return err
	}
	switch {
	case strings.HasPrefix(answer, "+CMGS:"):
		return nil
	case answer == "ERROR":
		return fmt.Errorf("Sending message failed")
	default:
		return fmt.Errorf("Unexpected answer: %s", answer)
	}
}

func (g *GsmModem) PerformPinVerification() error {
	ready, err := g.IsSimReady()
	if err != nil {
		return err
	}

	if ready {
		return nil
	}

	err = g.sendModemCommand(fmt.Sprintf("AT+CPIN=\"%s\"", g.simPin))
	answer, err := g.readNonEmptyLine()
	if err != nil {
		return err
	}
	if answer != "OK" {
		return fmt.Errorf("PIN could not be verified")
	}

	return nil
}

func (g *GsmModem) Close() {
	g.port.Close()
}

func (g *GsmModem) Init() error {
	err := g.EchoOff()
	if err != nil {
		return err
	}

	err = g.PerformPinVerification()
	if err != nil {
		return err
	}

	return nil
}

type DummyModem struct{}

func NewDummyModem() (*DummyModem, error) {
	return &DummyModem{}, nil
}

func (d *DummyModem) Init() error { return nil }

func (d *DummyModem) SendMessage(phoneNr string, message string) error {
	fmt.Printf("DummyModem: SendMessage to %s: %s\n", phoneNr, message)
	return nil
}

func (d *DummyModem) Close() {}
