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
which performs cross compilation to an ARMv8 Linux target (i.e. a Respberry PI 3 or later) is also provided. When started the
following environment variables can be set in order to configure the behaviour of `smssender`.

# Calling the REST service
