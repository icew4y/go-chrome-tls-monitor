# Go Chrome TLS Monitor

A Go application that monitors TLS fingerprint changes using Chrome browser in a headless mode.

## Features

- Monitors TLS fingerprint changes on target URLs
- Webhook notifications on fingerprint changes
- Docker support with Windows containers

## Quick Start

### Local Development

1. Install dependencies:
   - Go 1.24+
   - Chrome browser

2. Copy and edit the configuration:
   ```bash
   cp config.yaml.example config.yaml
   ```

3. Run the application:
   ```bash
   go run main.go
   ```

### Docker

Build and run using Docker:

```bash
# Create local data directory
New-Item -ItemType Directory -Path "C:\ChromeTLSData" -Force

# Build the image
docker build -t go-chrome-tls-monitor .

# Run the container
docker run -p 8080:8080 go-chrome-tls-monitor

# Run interactively
docker run -it --rm go-chrome-tls-monitor "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

# Run Windows container with volume mount
docker run -d --name chrome-tls-monitor -v "C:\ChromeTLSData:C:\app\data" -p 8080:8080 --restart unless-stopped go-chrome-tls-monitor

```

## Configuration

Edit `config.yaml` to configure:

## API Endpoints

- `GET /healthz`: Health check

## Troubleshooting

### Docker Build Issues on Windows

#### Chocolatey Installation Fails with DNS Resolution Errors

If you encounter errors like `"The remote name could not be resolved: 'chocolatey.org'"` during Docker build, this is a common issue with Windows Docker containers not having proper DNS resolution.

**Solution:**

1. **Edit Docker Daemon Configuration:**
   - Open Docker Desktop on Windows/Mac
   - Go to **Settings** → **Docker Engine**
   - Add the following line at the bottom of the file, just above the last curly brace:
   ```json
   "dns": ["8.8.8.8"]
   ```

2. **Example Docker Daemon Configuration:**
   ```json
   {
     "registry-mirrors": [],
     "insecure-registries": [],
     "debug": false,
     "experimental": false,
     "dns": ["8.8.8.8"]
   }
   ```

3. **Restart Docker Desktop** for changes to take effect

4. **Rebuild your image:**
   ```bash
   docker build -t go-chrome-tls-monitor .
   ```

**Note:** This fixes DNS resolution issues in Windows containers by explicitly setting Google's DNS server (8.8.8.8) for Docker containers.

**Source:** [Stack Overflow - Can't install Chocolatey into Windows Docker container](https://stackoverflow.com/questions/67287347/can-t-install-choclatey-into-windows-docker-container)

## License


