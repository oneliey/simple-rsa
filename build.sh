#!/bin/bash

# darwin/arm64
GOOS=darwin GOARCH=arm64 go build -o ./bin/darwin/simpleRSA-darwin-arm64
GOOS=darwin GOARCH=arm64 go build -o bin/simpleRSA.app/Contents/MacOS/simpleRSA

# darwin/amd64
GOOS=darwin GOARCH=amd64 go build -o ./bin/darwin/simpleRSA-darwin-amd64
GOOS=darwin GOARCH=amd64 go build -o bin/simpleRSA-amd64.app/Contents/MacOS/simpleRSA-amd64

# linux/amd64
GOOS=linux GOARCH=amd64 go build -o ./bin/linux/simpleRSA-linux-amd64

# windows/amd64
GOOS=windows GOARCH=amd64 go build -o ./bin/windows/simpleRSA-windows-amd64.exe