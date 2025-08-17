# Use Windows Server Core as base image
FROM mcr.microsoft.com/windows/servercore:ltsc2025

# Set cmd as the default shell initially
# SHELL ["cmd", "/S", "/C"]
SHELL ["powershell", "-Command", "$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue';"]

ADD Files/FontsToAdd.tar /Fonts/
WORKDIR /Fonts/
RUN .\Add-Font.ps1 Fonts


# Install chocolatey
RUN iwr https://chocolatey.org/install.ps1 -UseBasicParsing | iex

# Install tools
RUN choco install -y curl golang --no-progress

# Set Go environment variables for Docker (Go is installed to Program Files by Chocolatey)
ENV GOPATH="C:\go"
ENV GOROOT="C:\Program Files\Go"

# Test with full paths
RUN Write-Host "Testing curl..."; curl.exe --version
RUN Write-Host "Testing go..."; go.exe version

# # Install Chrome via direct download from Google
RUN curl.exe -L "https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi" -o chrome.msi
RUN Start-Process msiexec.exe -Wait -ArgumentList '/i chrome.msi /quiet /norestart'
RUN Remove-Item chrome.msi


# Set working directory
WORKDIR C:/app

# Copy go module files first for better caching
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the rest of the application files
COPY . .

# Build the Go application (pure Go SQLite, no CGO needed)
ENV CGO_ENABLED=0
RUN go build -o go-chrome-tls-monitor.exe .

# Create directories for Chrome and database
RUN New-Item -ItemType Directory -Path C:\chrome-data -Force
RUN New-Item -ItemType Directory -Path C:\app\data -Force

# Create volume for persistent database storage
VOLUME ["C:/app/data"]

# Expose the HTTP port (default is 8080 based on config)
EXPOSE 8080

# Set Chrome path environment variable to point to the installed location
ENV CHROME_PATH="C:\Program Files\Google\Chrome\Application\chrome.exe"

# Run the application
CMD ["go-chrome-tls-monitor.exe"]
