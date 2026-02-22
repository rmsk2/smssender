// @title           GSM Modem SMS Sender API
// @version         1.2.4
// @description     Sends SMS messages via a locally attached GSM modem. Requests are authenticated using a JWT supplied in the X-Token header.
//
// @securityDefinitions.apikey XTokenAuth
// @in              header
// @name            X-Token
// @description     JWT token for authentication. Audience must match GSM_MODEM_ALLOWED_AUDIENCE and issuer must match GSM_MODEM_NAME_ISSUER.

package main

import (
	"context"
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
	"sync"
	"syscall"

	_ "gsmmodem/docs"

	httpSwagger "github.com/swaggo/http-swagger/v2"
)

const programVersion = "1.2.4"
const gsmModemFileRoot = "GSM_MODEM_FILE_ROOT"
const gsmModemAllowedAudience = "GSM_MODEM_ALLOWED_AUDIENCE"
const gsmModemSigningSecret = "GSM_MODEM_SIGNING_SECRET"
const gsmModemVerificationSecret = "GSM_MODEM_VERIFICATION_SECRET"
const gsmModemFileCert = "GSM_MODEM_FILE_CERT"
const gsmModemFileKey = "GSM_MODEM_FILE_KEY"
const gsmModemNameIssuer = "GSM_MODEM_NAME_ISSUER"
const gsmModemSimPin = "GSM_MODEM_SIM_PIN"
const gsmmodemPort = "GSM_MODEM_SERIAL_PORT"
const gsmmodemServerPort = "GSM_MODEM_LISTENER_PORT"
const gsmModemTokenType = "GSM_MODEM_TOKEN_TYPE"
const gsmModemDummy = "GSM_MODEM_DUMMY"
const authHeaderName = "X-Token"

// SendRequest holds the parameters for an SMS send operation.
type SendRequest struct {
	// The text of the SMS. Max 160 characters. German umlauts are supported.
	Message string `json:"message" example:"Hello, this is a test message"`
	// Recipient phone number with country code, without leading plus sign.
	PhoneNr string `json:"phone_nr" example:"4915123456789"`
}

type smsSender struct {
	allowedAudience    string
	fileNameRoot       string
	fileNameCert       string
	fileNameKey        string
	expectedIssuerName string
	signingSecret      []byte
	signerGen          func([]byte) *jwt.JwtSigner
	verificationSecret []byte
	verifierGen        func([]byte) *jwt.JwtVerifier
	simPin             string
	port               string
	senderQueue        chan SendRequest
	modem              Modem
	serverPort         uint16
	canSign            bool
	useDummy           bool
}

func newSmsSender() *smsSender {
	res := smsSender{
		allowedAudience:    "local_sms_sender",
		fileNameRoot:       "private-tls-ca.pem",
		fileNameCert:       "server.crt",
		fileNameKey:        "server.pem",
		expectedIssuerName: "daheim_token_issuer",
		signingSecret:      []byte("a-string-secret-at-least-256-bits-long"),
		signerGen:          jwt.NewHs256JwtSigner,
		verificationSecret: []byte("a-string-secret-at-least-256-bits-long"),
		verifierGen:        jwt.NewHs256JwtVerifier,
		simPin:             "0000",
		senderQueue:        make(chan SendRequest, 10),
		port:               "/dev/ttyUSB0",
		serverPort:         4443,
		canSign:            true,
	}

	return &res
}

// sendFunc handles incoming SMS send requests.
//
// @Summary      Send an SMS message
// @Description  Queues an SMS message for delivery via the attached GSM modem. The request body must be valid JSON containing the recipient phone number and message text.
// @Tags         sms
// @Accept       json
// @Param        request  body      SendRequest true  "SMS send request"
// @Success      200      "Message queued successfully"
// @Failure      400      {string}  string      "Invalid request body"
// @Failure      401      {string}  string      "Authentication failed — JWT missing or invalid"
// @Failure      403      {string}  string      "Authentication failed — wrong audience or issuer"
// @Failure      500      {string}  string      "Internal server error"
// @Security     XTokenAuth
// @Router       /localsender/send [post]
func (s *smsSender) sendFunc(w http.ResponseWriter, r *http.Request) {
	jwtVerifier := s.verifierGen(s.verificationSecret)

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
	if s.useDummy {
		s.modem, err = NewDummyModem()
	} else {
		s.modem, err = NewGsmModem(s.simPin, s.port)
	}
	if err != nil {
		return err
	}
	return s.modem.Init()
}

func (s *smsSender) StartProcessor(wg *sync.WaitGroup) {
	wg.Add(1)
	go s.smsProcessor(wg)
}

func (s *smsSender) smsProcessor(wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		request, ok := <-s.senderQueue
		if !ok {
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
}

func (s *smsSender) evalEnvironment() error {
	var ok bool
	hmacInUse := true

	temp, ok := os.LookupEnv(gsmModemNameIssuer)
	if ok {
		s.expectedIssuerName = temp
	}

	tokenType, ok := os.LookupEnv(gsmModemTokenType)
	if ok {
		switch tokenType {
		case jwt.AlgEs256:
			s.signerGen = jwt.NewEs256JwtSigner
			s.verifierGen = jwt.NewEs256JwtVerifier
			hmacInUse = false
			log.Printf("Using ECDSA-256 JWTs")
		case jwt.AlgEs384:
			s.signerGen = jwt.NewEs384JwtSigner
			s.verifierGen = jwt.NewEs384JwtVerifier
			hmacInUse = false
			log.Printf("Using ECDSA-384 JWTs")
		case jwt.AlgHs384:
			s.signerGen = jwt.NewHs384JwtSigner
			s.verifierGen = jwt.NewHs384JwtVerifier
			hmacInUse = true
			log.Printf("Using HMAC SHA-384 JWTs")
		default:
			s.signerGen = jwt.NewHs256JwtSigner
			s.verifierGen = jwt.NewHs256JwtVerifier
			hmacInUse = true
			log.Printf("Using HMAC SHA-256 JWTs")
		}
	} else {
		s.signerGen = jwt.NewHs256JwtSigner
		s.verifierGen = jwt.NewHs256JwtVerifier
		hmacInUse = true
		log.Printf("Using HMAC SHA-256 JWTs")
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

	temp, ok = os.LookupEnv(gsmModemVerificationSecret)
	if ok {
		s.verificationSecret = []byte(temp)
	}

	if hmacInUse {
		// When using an HMAC the two secrets are the same and all secrets are valid
		s.signingSecret = s.verificationSecret
		s.canSign = true
	} else {
		// Check if verfication secret is valid. We need at least
		// the verification secret.
		_, err := jwt.LoadEcdsaPublicKey(s.verificationSecret)
		if err != nil {
			return err
		}

		temp, ok = os.LookupEnv(gsmModemSigningSecret)
		if ok {
			s.signingSecret = []byte(temp)

			// Verify signing secret
			_, err := jwt.LoadEcdsaPrivateKey(s.signingSecret)
			if err != nil {
				log.Printf("No valid signing secret provided: %v", err)
			}

			s.canSign = (err == nil)
		} else {
			s.canSign = false
			log.Println("No signing secret provided")
		}
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

	_, s.useDummy = os.LookupEnv(gsmModemDummy)

	return nil
}

func (s *smsSender) InstallSignalHandler(server *http.Server) {
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan
		server.Shutdown(context.Background())
	}()
}

func (s *smsSender) genToken(subject string) {
	if !s.canSign {
		log.Println("Can not create token. No signing secret configured")
		return
	}
	jwtIssuer := s.signerGen(s.signingSecret)
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
	http.HandleFunc("/swagger/", httpSwagger.Handler(
		httpSwagger.URL("/swagger/doc.json"),
	))

	log.Printf("SMS-Sender. Version: %s", programVersion)
	log.Println("Initializing modem")
	err = sender.initModem()
	if err != nil {
		log.Fatal("Unable to initialize modem: ", err)
	}
	log.Println("Modem is initialized")

	var wg sync.WaitGroup
	sender.StartProcessor(&wg)
	sender.InstallSignalHandler(server)

	err = server.ListenAndServeTLS(sender.fileNameCert, sender.fileNameKey)
	if err != nil && err != http.ErrServerClosed {
		log.Println(err)
	}

	close(sender.senderQueue)
	wg.Wait()
	log.Println("Server stopped")
}
