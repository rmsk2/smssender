# About
In my [mobilenotifier](https://github.com/rmsk2/mobilenotifier) project I need functionality to send SMS (text) messages to
the recipients of notifications. In a first implementation I used IFTTT to achieve this goal. IFTTT allows to define a webhook
which, if called, causes an Android mobile phone, on which the IFTTT app is installed, to send a text message to predefined receivers.
Apart from working around power management functions on the phone in order to force the immediate sending of the text message on the
phone this worked satisfactorily, but is rather convoluted. In the end a more direct approach was more appealing to me.

I bought a GSM modem based on the Wavecom Q2303A chipset which connects via USB to a machine and allows to send SMS messages via
old fashioned AT commands. This software, if run on a machine to which such a modem is connected, provides a REST service which
allows to send SMS messages to arbitrary recipients.

# Building and installing
The software depends on [go.bug.st/serial](https://github.com/bugst/go-serial), a library which allows go code to talk to RS-232
serial devices. After installing `go-serial` the service can be built by executing `go build`. A primitive script (`build_raspi.sh`) 
which performs cross compilation to a (64 bit) ARMv8  Linux target (i.e. a Raspberry Pi 3 or later) is also provided. Authentication
is based on an HMACed JWT. The JWT could be issued by [tokenissuer](https://github.com/rmsk2/tokenissuer) or via `smssender` itself.
At the moment all valid tokens are accepted independent of their issung date. When started the following environment variables can be
set in order to configure the behaviour of `smssender`.

| Variable | Value |
|-|-|
|`GSM_MODEM_FILE_ROOT`| Name of a file in which the root certificate for the server cert is stored. Default value: `private-tls-ca.pem`. |
|`GSM_MODEM_ALLOWED_AUDIENCE`| The expected `aud` value in the JWT. Default value: `local_sms_sender`|
|`GSM_MODEM_HMAC_SECRET`| The HMAC secret to generate and verify JWTs. Default value: `a-string-secret-at-least-256-bits-long`|
|`GSM_MODEM_FILE_CERT`| File which holds the TLS server cert used by `smssender`. Default value: `server.crt`|
|`GSM_MODEM_FILE_KEY`| File which holds the TLS server cert private key used by `smssender`. Default value: `server.pem`|
|`GSM_MODEM_NAME_ISSUER`| The expected `iss` value in the JWT. Default value: `daheim_token_issuer`|
|`GSM_MODEM_SIM_PIN`| The PIN of the SIM card in the modem. Default value: `0000`|
|`GSM_MODEM_PORT`| The serial device to to be used. Default value: `/dev/ttyUSB0`|

As the software needs to be executed on a machine to which a modem is connected it is a bit difficult to run it in a kubernetes cluster.
When started with the option `-t` `smssender` creates a JWT and exits. This can be used to generate a token for `mobilenotifier`.

# Calling the REST service

The service listens on port 4443. You can send an SMS by transmitting a `POST` request to the path `/localsender/send` with a JSON body
of the following form:

```
{
    "message": "This is a test message",
    "phone_nr" "4912345678901"
}
```

At least when using the Wavecom Q2303A the phone number has to start with the country code (i.e. here 49 for Germany). The JWT has to
be provided in a header with the key `X-Token`.