#!/bin/bash

##########################################################################################
# NOTE: You are expected to call this file from the Makefile at the root of this project #
##########################################################################################

APPLICATION_NAME="whois"

mkdir bin
rm -rf bin/${APPLICATION_NAME}-*.zip

env GOOS=darwin GOARCH=amd64 go build -mod vendor -o ${APPLICATION_NAME}
chmod +x ${APPLICATION_NAME}
zip bin/${APPLICATION_NAME}-darwin-amd64.zip ${APPLICATION_NAME} -m

env GOOS=darwin GOARCH=arm64 go build -mod vendor -o ${APPLICATION_NAME}
chmod +x ${APPLICATION_NAME}
zip bin/${APPLICATION_NAME}-darwin-arm64.zip ${APPLICATION_NAME} -m

env GOOS=linux GOARCH=amd64 go build -mod vendor -o ${APPLICATION_NAME}
chmod +x ${APPLICATION_NAME}
zip bin/${APPLICATION_NAME}-linux-amd64.zip ${APPLICATION_NAME} -m

env GOOS=linux GOARCH=arm64 go build -mod vendor -o ${APPLICATION_NAME}
chmod +x ${APPLICATION_NAME}
zip bin/${APPLICATION_NAME}-linux-arm64.zip ${APPLICATION_NAME} -m

env GOOS=windows GOARCH=amd64 go build -mod vendor -o ${APPLICATION_NAME}.exe
chmod +x ${APPLICATION_NAME}.exe
zip bin/${APPLICATION_NAME}-windows-amd64.zip ${APPLICATION_NAME}.exe -m
