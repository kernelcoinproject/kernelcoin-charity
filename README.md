# kernelcoin-charity
free coins

## Screenshots

## Basic Setup

Get yourself a cloud hosted vm and connect via ssh

As non root user

1. Setup kernelcoind

```
mkdir -p kernelcoin
cd kernelcoin
wget https://github.com/kernelcoinproject/kernelcoin/releases/download/main/kernelcoin-0.21.4-x86_64-linux-gnu.tar.gz
tar xf kernelcoin-0.21.4-x86_64-linux-gnu.tar.gz
```

```
mkdir -p ~/.kernelcoin
cat > ~/.kernelcoin/kernelcoin.conf << EOF
# enable p2p
listen=1
txindex=1
logtimestamps=1
server=1
rpcuser=mike
rpcpassword=x
rpcport=9332
rpcallowip=127.0.0.1
rpcbind=127.0.0.1
EOF
```

```
./kernelcoind
```
```
./kernelcoin-cli createwallet "main"
./kernelcoin-cli getnewaddress "" legacy
```

2. Download and run the charity binary

```
cd ~
mkdir -p kernelcoin-charity
cd kernelcoin-charity
wget https://github.com/kernelcoinproject/kernelcoin-charity/releases/download/main/charity-server-lin-x86_x64.tar.gz
tar xf charity-server-lin-x86_x64.tar.gz
cat > start.sh << EOF
export KERNELCOIN_RPC_URL="http://127.0.0.1:9332"
export KERNELCOIN_RPC_USER="mike"
export KERNELCOIN_RPC_PASS="x"
# https://www.google.com/recaptcha/admin update index.html as well line ~617 
export RECAPTCHA_SECRET_KEY="YOUR_SECRET_KEY_HERE"
# update address
export CHARITY_ADDRESS="KNkebi6ybfjBUQmZic4naE4rSDjQC1N4AS"
#export CHARITY_WIF="..."
./charity-server-lin-x86_x64
EOF
chmod +x start.sh
./start.sh
```


3. Setup caddy to host via https with username and password

As root
```
mkdir -p /opt/caddy
cd /opt/caddy
wget https://github.com/caddyserver/caddy/releases/download/v2.10.2/caddy_2.10.2_linux_amd64.tar.gz
tar xf caddy_2.10.2_linux_amd64.tar.gz
```

```
DOMAIN="website.duckdns.org"
CADDYUSER="admin"
CADDYPASS=$(/opt/caddy/caddy hash-password -p "REPLACEPASSWORD")

cat > /opt/caddy/Caddyfile << EOF
$DOMAIN {

    basic_auth {
        admin $CADDYPASS
    }

    header {
        X-Content-Type-Options "nosniff"
        X-Frame-Options "SAMEORIGIN"
        X-XSS-Protection "1; mode=block"
        Referrer-Policy "strict-origin-when-cross-origin"
    }

    encode gzip

    log {
        output file /var/log/caddy/wallet.log {
            roll_size 100mb
            roll_keep 5
        }
        format json
    }

    reverse_proxy 127.0.0.1:8080
}
EOF
/opt/caddy/caddy run
```

4. Run it all at boot via tmux

Run as root user (port 443 requires root)
```
yum install -y tmux cronie
cat > /root/startWeb.sh << EOF
tmux kill-session -t caddy 2>/dev/null
tmux new -s caddy -d
tmux send-keys -t caddy "cd /opt/caddy && ./caddy run" C-m
EOF
chmod +x /root/startWeb.sh
```

Run as root user
```
crontab -e
@reboot /root/startWeb.sh
```

Run as non-root user
```

cat > /home/ec2-user/startup.sh << EOF
tmux kill-session -t charity 2>/dev/null
tmux new -s charity -d
tmux neww -t charity -n kernelcoin
tmux neww -t charity -n server
tmux send-keys -t charity:kernelcoin "cd /home/ec2-user/kernelcoin && ./kernelcoind" C-m
tmux send-keys -t charity:server "cd /home/ec2-user/kernelcoin-charity && ./start.sh" C-m
EOF
chmod +x /home/ec2-user/startup.sh
```

Run as non-root user
```
crontab -e
@reboot /home/ec2-user/startup.sh
```


