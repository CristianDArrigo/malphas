FROM python:3.12-slim

RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends tor procps && \
    rm -rf /var/lib/apt/lists/*

# Configure Tor
RUN sed -i 's/#ControlPort 9051/ControlPort 9051/' /etc/tor/torrc && \
    sed -i 's/#CookieAuthentication 1/CookieAuthentication 1/' /etc/tor/torrc && \
    mkdir -p /var/lib/tor/malphas_hs && \
    chown -R debian-tor:debian-tor /var/lib/tor/malphas_hs && \
    chmod 700 /var/lib/tor/malphas_hs

# Install malphas
WORKDIR /app
COPY pyproject.toml .
COPY src/ src/
RUN pip install --no-cache-dir -e .

# Entrypoint script: starts Tor, fixes permissions, launches malphas
RUN cat > /entrypoint.sh << 'EOF'
#!/bin/bash
service tor start
sleep 3
chmod o+r /run/tor/control.authcookie 2>/dev/null
exec malphas "$@"
EOF
RUN chmod +x /entrypoint.sh

# Persist address book and pins across restarts
VOLUME /root/.malphas

ENTRYPOINT ["/entrypoint.sh"]
CMD ["--tor", "--port", "7777"]
