package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"gsmmodem/jwt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
)

const programVersion = "1.1.0"
const gsmModemFileRoot = "GSM_MODEM_FILE_ROOT"
const gsmModemAllowedAudience = "GSM_MODEM_ALLOWED_AUDIENCE"
const gsmModemHmacSecret = "GSM_MODEM_HMAC_SECRET"
const gsmModemFileCert = "GSM_MODEM_FILE_CERT"
const gsmModemFileKey = "GSM_MODEM_FILE_KEY"
const gsmModemNameIssuer = "GSM_MODEM_NAME_ISSUER"
const gsmModemSimPin = "GSM_MODEM_SIM_PIN"
const gsmmodemPort = "GSM_MODEM_SERIAL_PORT"
const gsmmodemServerPort = "GSM_MODEM_LISTENER_PORT"
const authHeaderName = "X-Token"

type SendRequest struct {
	Message string `json:"message"`
	PhoneNr string `json:"phone_nr"`
}

type smsSender struct {
	allowedAudience    string
	fileNameRoot       string
	fileNameCert       string
	fileNameKey        string
	expectedIssuerName string
	tokenSecret        []byte
	simPin             string
	port               string
	senderQueue        chan SendRequest
	modem              Modem
	doStop             bool
	serverPort         uint16
}

func newSmsSender() *smsSender {
	res := smsSender{
		allowedAudience:    "local_sms_sender",
		fileNameRoot:       "private-tls-ca.pem",
		fileNameCert:       "server.crt",
		fileNameKey:        "server.pem",
		expectedIssuerName: "daheim_token_issuer",
		tokenSecret:        []byte("a-string-secret-at-least-256-bits-long"),
		simPin:             "0000",
		senderQueue:        make(chan SendRequest, 10),
		port:               "/dev/ttyUSB0",
		doStop:             false,
		serverPort:         4443,
	}

	return &res
}

func (s *smsSender) sendFunc(w http.ResponseWriter, r *http.Request) {
	jwtVerifier := jwt.NewHs256JwtVerifier(s.tokenSecret)

	token := r.Header.Get(authHeaderName)
	parsedClaims, err := jwtVerifier.VerifyJwt(token)
	if err != nil {
		log.Printf("Unable to authenticate client: %v", err)
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return
	}

	tokenAudience := parsedClaims["aud"]
	tokenIssuer := parsedClaims["iss"]
	client := parsedClaims["sub"]

	if tokenAudience != s.allowedAudience {
		log.Printf("Unable to authenticate client. Wrong audience: %v", tokenAudience)
		http.Error(w, "Authentication failed", http.StatusForbidden)
		return
	}

	if tokenIssuer != s.expectedIssuerName {
		log.Printf("Unable to authenticate client. Wrong issuer: %v", tokenIssuer)
		http.Error(w, "Authentication failed", http.StatusForbidden)
		return
	}

	log.Printf("Received request from '%s'", client)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println("Unable to read body")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var i SendRequest
	err = json.Unmarshal(body, &i)
	if err != nil {
		log.Printf("Unable to parse body: '%s'", string(body))
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	go func(i SendRequest) {
		log.Printf("Received request from '%s' for '%s'", client, i.PhoneNr)
		s.senderQueue <- i
	}(i)
}

func (s *smsSender) initModem() error {
	var err error
	s.modem, err = NewGsmModem(s.simPin, s.port)
	if err != nil {
		return err
	}
	return s.modem.Init()
}

func (s *smsSender) smsProcessor() {
	for !s.doStop {
		request := <-s.senderQueue
		if s.doStop {
			break
		}

		log.Printf("Sending message to '%s'", request.PhoneNr)

		message := transformMessageText(request.Message)

		err := s.modem.SendMessage(request.PhoneNr, message)
		if err != nil {
			log.Printf("Unable to send message to '%s': %v", request.PhoneNr, err)
			continue
		}

		log.Printf("Message successfully sent to '%s'", request.PhoneNr)
	}

	log.Println("Closing modem")
	s.modem.Close()
	log.Println("Modem closed")
	os.Exit(0)
}

func (s *smsSender) evalEnvironment() error {
	var ok bool

	temp, ok := os.LookupEnv(gsmModemNameIssuer)
	if ok {
		s.expectedIssuerName = temp
	}

	temp, ok = os.LookupEnv(gsmModemFileRoot)
	if ok {
		s.fileNameRoot = temp
	}

	temp, ok = os.LookupEnv(gsmModemFileCert)
	if ok {
		s.fileNameCert = temp
	}

	temp, ok = os.LookupEnv(gsmModemFileKey)
	if ok {
		s.fileNameKey = temp
	}

	s.simPin, ok = os.LookupEnv(gsmModemSimPin)
	if !ok {
		return fmt.Errorf("You have to specify a PIN for the SIM card in the modem")
	}

	temp, ok = os.LookupEnv(gsmModemHmacSecret)
	if ok {
		s.tokenSecret = []byte(temp)
	}

	temp, ok = os.LookupEnv(gsmModemAllowedAudience)
	if ok {
		s.allowedAudience = temp
	}

	temp, ok = os.LookupEnv(gsmmodemPort)
	if ok {
		s.port = temp
	}

	temp, ok = os.LookupEnv(gsmmodemServerPort)
	if ok {
		p, err := strconv.ParseUint(temp, 10, 16)
		if err != nil {
			return fmt.Errorf("Illegal port number: %v", err)
		}

		s.serverPort = uint16(p)
	}

	return nil
}

func (s *smsSender) InstallSignalHandler() {
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan
		s.doStop = true
		close(s.senderQueue)
	}()
}

func (s *smsSender) genToken(subject string) {
	jwtIssuer := jwt.NewHs256JwtSigner(s.tokenSecret)
	claims := jwt.MakeClaims(subject, s.allowedAudience, s.expectedIssuerName)
	token, _ := jwtIssuer.CreateJwt(claims)
	fmt.Println(token)
}

func main() {
	smsSenderFlags := flag.NewFlagSet("gsmmodem", flag.ContinueOnError)
	tokenSubject := smsSenderFlags.String("t", "", "Generate token and exit")

	err := smsSenderFlags.Parse(os.Args[1:])
	if err != nil {
		fmt.Println(err)
		os.Exit(42)
	}

	sender := newSmsSender()
	err = sender.evalEnvironment()
	if err != nil {
		log.Fatal("Unable to eval environment: ", err)
	}

	if *tokenSubject != "" {
		sender.genToken(*tokenSubject)
		os.Exit(0)
	}

	caCert, err := os.ReadFile(sender.fileNameRoot)
	if err != nil {
		log.Fatal("Error reading root certificate: ", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		log.Fatal("Failed to parse root certificate")
	}

	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.NoClientCert,
		MinVersion: tls.VersionTLS12,
	}

	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", sender.serverPort),
		TLSConfig: tlsConfig,
	}

	http.HandleFunc("POST /localsender/send", sender.sendFunc)

	log.Printf("SMS-Sender. Version: %s", programVersion)
	log.Println("Initializing modem")
	err = sender.initModem()
	if err != nil {
		log.Fatal("Unable to initialize modem: ", err)
	}
	log.Println("Modem is initialized")

	go sender.smsProcessor()
	sender.InstallSignalHandler()

	err = server.ListenAndServeTLS(sender.fileNameCert, sender.fileNameKey)
	if err != nil {
		panic(err)
	}
}
