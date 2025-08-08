# setup Go
FROM golang:1.24 AS gobuilder

# install subfinder
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# install httpx
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# create python image
FROM python:3.11-slim

# install basic system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates curl unzip git && \
    rm -rf /var/lib/apt/lists/*

# copy subfinder and httpx from Go builder
COPY --from=gobuilder /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=gobuilder /go/bin/httpx /usr/local/bin/httpx

# install python dependencies
RUN pip install --no-cache-dir requests pyyaml

# create working directory
WORKDIR /app

# copy your script into container
COPY assetmonitor.py /app/assetmonitor.py

# make script executable
RUN chmod +x /app/assetmonitor.py

# set default entrypoint
ENTRYPOINT ["python", "/app/assetmonitor.py"]
