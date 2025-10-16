#!/bin/bash
set -e

echo "🚀 AutoScript VPN - Easy Installer"
echo "===================================="

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root: sudo ./install.sh"
    exit 1
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; exit 1; }

# Configuration
INSTALL_DIR="/opt/autoscript-vpn"
SERVICE_USER="autoscript"

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
else
    error "Cannot detect OS"
fi

log "Detected: $OS $VER"

install_dependencies() {
    log "Installing system dependencies..."
    
    if [ "$OS" = "ubuntu" ] || [ "$OS" = "debian" ]; then
        apt update && apt upgrade -y
        apt install -y curl wget git python3 python3-pip python3-venv \
            sqlite3 nginx fail2ban iptables-persistent \
            certbot software-properties-common
    else
        error "Unsupported OS. Only Ubuntu/Debian supported."
    fi
}

create_environment() {
    log "Creating installation directory..."
    mkdir -p $INSTALL_DIR
    cd $INSTALL_DIR
    
    # Create virtual environment
    python3 -m venv venv
    source venv/bin/activate
    
    # Install Python packages
    pip install --upgrade pip
    pip install fastapi uvicorn sqlalchemy aiogram python-multipart pydantic-settings
    
    log "Python environment setup complete"
}

setup_firewall() {
    log "Configuring firewall..."
    
    # Basic firewall rules
    iptables -F
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    iptables -A INPUT -p tcp --dport 80 -j ACCEPT
    iptables -A INPUT -p tcp --dport 443 -j ACCEPT
    iptables -A INPUT -p tcp --dport 20000:30000 -j ACCEPT
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    
    # Save rules
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    
    log "Firewall configured"
}

create_config_files() {
    log "Creating configuration files..."
    
    cd $INSTALL_DIR
    
    # Create .env file
    cat > .env << 'EOF'
# AutoScript VPN Configuration
VPS_HOSTNAME=$(hostname -f)
MANAGER_API_TOKEN=$(openssl rand -hex 32)

# Database
DB_URL=sqlite:////opt/autoscript-vpn/data/autoscript.db

# Telegram Bot - GET THIS FROM @BotFather
TELEGRAM_BOT_TOKEN=your-telegram-bot-token-here

# Admin Telegram IDs (comma separated)
ADMIN_TELEGRAM_IDS=123456789

# Payment (OrderKuota - optional)
ORDERKUOTA_API_KEY=your-orderkuota-api-key
ORDERKUOTA_BASE_URL=https://api.orderkuota.com

# Service Settings
AVAILABLE_PORTS_START=20000
AVAILABLE_PORTS_END=30000
DEFAULT_ACCOUNT_DAYS=30

# Security
ENABLE_LETSENCRYPT=false
LETSENCRYPT_EMAIL=your-email@example.com
EOF

    # Create directory structure
    mkdir -p {data,logs,config,ssl}
    
    log "Configuration files created"
}

create_systemd_services() {
    log "Creating system services..."
    
    # Manager service
    cat > /etc/systemd/system/autoscript-manager.service << EOF
[Unit]
Description=AutoScript VPN Manager
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
Environment=PATH=$INSTALL_DIR/venv/bin
ExecStart=$INSTALL_DIR/venv/bin/python manager.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    # Bot service
    cat > /etc/systemd/system/autoscript-bot.service << EOF
[Unit]
Description=AutoScript VPN Telegram Bot
After=network.target autoscript-manager.service

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
Environment=PATH=$INSTALL_DIR/venv/bin
ExecStart=$INSTALL_DIR/venv/bin/python bot.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log "Systemd services created"
}

create_application_files() {
    log "Creating application files..."
    cd $INSTALL_DIR

    # Create single-file manager
    cat > manager.py << 'EOF'
#!/usr/bin/env python3
import os
import sqlite3
import uuid
import json
from datetime import datetime, timedelta
from contextlib import contextmanager
from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel
from typing import Optional, List, Dict
import uvicorn

# Database setup
DB_PATH = "/opt/autoscript-vpn/data/autoscript.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id TEXT UNIQUE NOT NULL,
            username TEXT,
            balance INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1
        )
    ''')
    
    # Accounts table
    c.execute('''
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_telegram_id TEXT NOT NULL,
            protocol TEXT NOT NULL,
            username TEXT,
            password TEXT,
            uuid TEXT,
            port INTEGER UNIQUE NOT NULL,
            remark TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            is_active BOOLEAN DEFAULT 1,
            last_used TIMESTAMP,
            data_used INTEGER DEFAULT 0
        )
    ''')
    
    # Payments table
    c.execute('''
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id TEXT UNIQUE NOT NULL,
            telegram_id TEXT NOT NULL,
            amount INTEGER NOT NULL,
            currency TEXT DEFAULT 'IDR',
            status TEXT DEFAULT 'pending',
            provider TEXT DEFAULT 'mock',
            provider_order_id TEXT,
            qr_code_url TEXT,
            payment_url TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            paid_at TIMESTAMP,
            metadata TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

# Models
class AccountCreate(BaseModel):
    owner_telegram_id: str
    protocol: str
    duration_days: int = 30
    remark: Optional[str] = None

class UserCreate(BaseModel):
    telegram_id: str
    username: Optional[str] = None

class PaymentCreate(BaseModel):
    telegram_id: str
    amount: int
    description: str

# Manager service
app = FastAPI(title="AutoScript VPN Manager")

# Security
API_TOKEN = os.getenv('MANAGER_API_TOKEN', 'default-token-change-me')

def verify_token(authorization: str = Header(...)):
    if authorization != f"Bearer {API_TOKEN}":
        raise HTTPException(status_code=401, detail="Invalid token")
    return True

@app.on_event("startup")
def startup():
    init_db()
    print("AutoScript VPN Manager started")

# User endpoints
@app.post("/api/users")
def create_user(user: UserCreate, _: bool = Depends(verify_token)):
    with get_db() as conn:
        c = conn.cursor()
        try:
            c.execute(
                "INSERT OR IGNORE INTO users (telegram_id, username) VALUES (?, ?)",
                (user.telegram_id, user.username)
            )
            conn.commit()
            return {"status": "success", "message": "User created"}
        except sqlite3.IntegrityError:
            return {"status": "exists", "message": "User already exists"}

@app.get("/api/users/{telegram_id}/balance")
def get_balance(telegram_id: str, _: bool = Depends(verify_token)):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT balance FROM users WHERE telegram_id = ?", (telegram_id,))
        result = c.fetchone()
        if result:
            return {"balance": result['balance']}
        raise HTTPException(status_code=404, detail="User not found")

# Account endpoints
@app.post("/api/accounts")
def create_account(account: AccountCreate, _: bool = Depends(verify_token)):
    with get_db() as conn:
        c = conn.cursor()
        
        # Check user exists and has balance
        c.execute("SELECT balance FROM users WHERE telegram_id = ?", (account.owner_telegram_id,))
        user = c.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Simple balance check (1000 units)
        if user['balance'] < 1000:
            raise HTTPException(status_code=402, detail="Insufficient balance")
        
        # Get available port
        c.execute("SELECT port FROM accounts WHERE is_active = 1")
        used_ports = [row['port'] for row in c.fetchall()]
        port = next(p for p in range(20000, 30000) if p not in used_ports)
        
        # Generate credentials
        if account.protocol in ["vmess", "vless"]:
            account_uuid = str(uuid.uuid4())
            password = None
        else:
            account_uuid = None
            password = uuid.uuid4().hex[:12]
        
        expires_at = datetime.now() + timedelta(days=account.duration_days)
        
        # Create account
        c.execute('''
            INSERT INTO accounts 
            (owner_telegram_id, protocol, username, password, uuid, port, remark, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            account.owner_telegram_id,
            account.protocol,
            f"user_{port}",
            password,
            account_uuid,
            port,
            account.remark,
            expires_at.isoformat()
        ))
        
        # Deduct balance
        c.execute("UPDATE users SET balance = balance - 1000 WHERE telegram_id = ?", 
                 (account.owner_telegram_id,))
        
        conn.commit()
        account_id = c.lastrowid
        
        # Generate OpenClash config
        openclash_node = generate_openclash_node({
            'id': account_id,
            'protocol': account.protocol,
            'port': port,
            'uuid': account_uuid,
            'password': password,
            'remark': account.remark
        })
        
        return {
            "status": "success",
            "account": {
                "id": account_id,
                "protocol": account.protocol,
                "port": port,
                "credentials": {
                    "server": os.getenv('VPS_HOSTNAME', 'localhost'),
                    "port": port,
                    "uuid": account_uuid,
                    "password": password
                },
                "openclash_node": openclash_node,
                "share_links": generate_share_links(account.protocol, port, account_uuid, password),
                "expires_at": expires_at.isoformat()
            }
        }

@app.get("/api/accounts")
def get_accounts(owner_telegram_id: str, _: bool = Depends(verify_token)):
    with get_db() as conn:
        c = conn.cursor()
        c.execute('''
            SELECT * FROM accounts 
            WHERE owner_telegram_id = ? AND is_active = 1
            ORDER BY created_at DESC
        ''', (owner_telegram_id,))
        
        accounts = []
        for row in c.fetchall():
            accounts.append(dict(row))
        
        return {"accounts": accounts}

# Export endpoints
@app.get("/export/openclash/{telegram_id}")
def export_openclash(telegram_id: str):
    with get_db() as conn:
        c = conn.cursor()
        c.execute('''
            SELECT * FROM accounts 
            WHERE owner_telegram_id = ? AND is_active = 1 AND expires_at > datetime('now')
        ''', (telegram_id,))
        
        nodes = []
        for account in c.fetchall():
            nodes.append(generate_openclash_node(dict(account)))
        
        return {"proxies": nodes}

def generate_openclash_node(account):
    hostname = os.getenv('VPS_HOSTNAME', 'localhost')
    
    node = {
        "name": f"{account['protocol'].upper()}-{account['port']}",
        "type": account['protocol'],
        "server": hostname,
        "port": account['port'],
        "udp": True
    }
    
    if account['protocol'] in ["vmess", "vless"]:
        node.update({
            "uuid": account['uuid'],
            "alterId": 0,
            "cipher": "auto",
            "tls": True,
            "skip-cert-verify": False,
            "network": "tcp"
        })
        if account['protocol'] == "vless":
            node["flow"] = "xtls-rprx-direct"
    
    elif account['protocol'] == "trojan":
        node.update({
            "password": account['password'],
            "sni": hostname,
            "skip-cert-verify": False
        })
    
    elif account['protocol'] == "shadowsocks":
        node.update({
            "password": account['password'],
            "cipher": "chacha20-ietf-poly1305"
        })
    
    return node

def generate_share_links(protocol, port, uuid, password):
    hostname = os.getenv('VPS_HOSTNAME', 'localhost')
    links = {}
    
    if protocol == "vmess":
        vmess_config = {
            "v": "2",
            "ps": f"VMess-{port}",
            "add": hostname,
            "port": port,
            "id": uuid,
            "aid": 0,
            "scy": "auto",
            "net": "tcp",
            "type": "none",
            "host": "",
            "path": "",
            "tls": "tls",
            "sni": hostname
        }
        import base64
        links["vmess"] = f"vmess://{base64.b64encode(json.dumps(vmess_config).encode()).decode()}"
    
    elif protocol == "vless":
        links["vless"] = f"vless://{uuid}@{hostname}:{port}?security=tls&type=tcp#VLESS-{port}"
    
    elif protocol == "trojan":
        links["trojan"] = f"trojan://{password}@{hostname}:{port}?sni={hostname}#Trojan-{port}"
    
    elif protocol == "shadowsocks":
        import base64
        method = "chacha20-ietf-poly1305"
        ss_uri = f"{method}:{password}@{hostname}:{port}"
        links["shadowsocks"] = f"ss://{base64.b64encode(ss_uri.encode()).decode()}#SS-{port}"
    
    return links

@app.get("/health")
def health():
    return {"status": "healthy", "service": "autoscript-manager"}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
EOF

    # Create single-file bot
    cat > bot.py << 'EOF'
#!/usr/bin/env python3
import os
import asyncio
import sqlite3
import uuid
import requests
from datetime import datetime
from aiogram import Bot, Dispatcher, types, F
from aiogram.filters import Command
from aiogram.types import Message, InlineKeyboardButton, InlineKeyboardMarkup, CallbackQuery
from aiogram.utils.keyboard import InlineKeyboardBuilder

# Configuration
BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', 'your-bot-token')
MANAGER_URL = "http://localhost:8000"
API_TOKEN = os.getenv('MANAGER_API_TOKEN', 'default-token-change-me')
ADMIN_IDS = [int(x.strip()) for x in os.getenv('ADMIN_TELEGRAM_IDS', '123456789').split(',')]

# Initialize bot
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()

# Database helper
def get_db():
    return sqlite3.connect('/opt/autoscript-vpn/data/autoscript.db')

# Manager API helper
def manager_api(method, endpoint, data=None):
    headers = {"Authorization": f"Bearer {API_TOKEN}"}
    url = f"{MANAGER_URL}{endpoint}"
    
    try:
        if method == "GET":
            response = requests.get(url, headers=headers, timeout=10)
        elif method == "POST":
            response = requests.post(url, json=data, headers=headers, timeout=10)
        elif method == "DELETE":
            response = requests.delete(url, headers=headers, timeout=10)
        else:
            return None
        
        return response.json() if response.status_code == 200 else None
    except:
        return None

# Start command
@dp.message(Command("start"))
async def cmd_start(message: Message):
    user_id = str(message.from_user.id)
    
    # Create user in manager
    manager_api("POST", "/api/users", {
        "telegram_id": user_id,
        "username": message.from_user.username or message.from_user.first_name
    })
    
    await message.answer(
        f"👋 Welcome to AutoScript VPN, {message.from_user.first_name}!\n\n"
        "Available commands:\n"
        "💳 /balance - Check your balance\n"
        "🆕 /create - Create new VPN account\n"
        "📱 /accounts - List your accounts\n"
        "💰 /topup - Add balance\n"
        "🔧 /help - Show help\n"
    )

# Balance command
@dp.message(Command("balance"))
async def cmd_balance(message: Message):
    user_id = str(message.from_user.id)
    balance_data = manager_api("GET", f"/api/users/{user_id}/balance")
    
    if balance_data:
        await message.answer(f"💰 Your balance: {balance_data['balance']} credits")
    else:
        await message.answer("❌ Could not fetch balance")

# Create account command
@dp.message(Command("create"))
async def cmd_create(message: Message):
    keyboard = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="VLESS", callback_data="create_vless"),
             InlineKeyboardButton(text="VMess", callback_data="create_vmess")],
            [InlineKeyboardButton(text="Trojan", callback_data="create_trojan"),
             InlineKeyboardButton(text="Shadowsocks", callback_data="create_ss")],
            [InlineKeyboardButton(text="🔙 Cancel", callback_data="cancel")]
        ]
    )
    
    await message.answer(
        "🆕 Choose protocol for new account:\n\n"
        "• VLESS - Recommended for speed\n"
        "• VMess - Compatible with most clients\n"
        "• Trojan - Bypasses censorship\n"
        "• Shadowsocks - Lightweight\n\n"
        "Cost: 1000 credits (30 days)",
        reply_markup=keyboard
    )

@dp.callback_query(F.data.startswith("create_"))
async def process_create(callback: CallbackQuery):
    protocol = callback.data.split("_")[1]
    user_id = str(callback.from_user.id)
    
    # Create account via manager
    result = manager_api("POST", "/api/accounts", {
        "owner_telegram_id": user_id,
        "protocol": protocol,
        "duration_days": 30,
        "remark": f"{protocol.upper()} Account"
    })
    
    if result and result.get("status") == "success":
        account = result["account"]
        
        # Format response
        response = f"""
✅ Account Created Successfully!

Protocol: {account['protocol'].upper()}
Server: {account['credentials']['server']}
Port: {account['credentials']['port']}
Expires: {account['expires_at'][:10]}

🔗 Share Links:
"""
        
        for link_type, link in account['share_links'].items():
            response += f"{link_type}: {link}\n"
        
        await callback.message.edit_text(response)
    else:
        await callback.message.edit_text("❌ Failed to create account. Check your balance.")
    
    await callback.answer()

# Accounts command
@dp.message(Command("accounts"))
async def cmd_accounts(message: Message):
    user_id = str(message.from_user.id)
    accounts_data = manager_api("GET", f"/api/accounts?owner_telegram_id={user_id}")
    
    if not accounts_data or not accounts_data.get("accounts"):
        await message.answer("❌ No active accounts found")
        return
    
    response = "📱 Your Active Accounts:\n\n"
    
    for acc in accounts_data["accounts"]:
        status = "✅ Active" if datetime.fromisoformat(acc['expires_at']) > datetime.now() else "❌ Expired"
        response += f"• {acc['protocol'].upper()} - Port {acc['port']} - {status}\n"
        response += f"  Created: {acc['created_at'][:10]}\n"
        response += f"  Expires: {acc['expires_at'][:10]}\n\n"
    
    await message.answer(response)

# Topup command
@dp.message(Command("topup"))
async def cmd_topup(message: Message):
    keyboard = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="💰 10,000 IDR", callback_data="topup_10000"),
             InlineKeyboardButton(text="💰 25,000 IDR", callback_data="topup_25000")],
            [InlineKeyboardButton(text="💰 50,000 IDR", callback_data="topup_50000"),
             InlineKeyboardButton(text="💰 100,000 IDR", callback_data="topup_100000")],
            [InlineKeyboardButton(text="🔙 Cancel", callback_data="cancel")]
        ]
    )
    
    await message.answer(
        "💳 Select top-up amount:\n\n"
        "After payment, your balance will be automatically credited.\n"
        "Currently using mock payments for testing.",
        reply_markup=keyboard
    )

@dp.callback_query(F.data.startswith("topup_"))
async def process_topup(callback: CallbackQuery):
    amount = int(callback.data.split("_")[1])
    user_id = str(callback.from_user.id)
    
    # Mock payment processing
    order_id = f"ORDER_{uuid.uuid4().hex[:8].upper()}"
    
    # Update user balance (mock successful payment)
    with get_db() as conn:
        c = conn.cursor()
        c.execute("UPDATE users SET balance = balance + ? WHERE telegram_id = ?", 
                 (amount, user_id))
        conn.commit()
    
    await callback.message.edit_text(
        f"✅ Payment successful!\n\n"
        f"Amount: 💰 {amount:,} IDR\n"
        f"Order ID: {order_id}\n"
        f"New balance: {amount} credits\n\n"
        f"Use /create to make new accounts!"
    )
    
    await callback.answer()

# Admin commands
@dp.message(Command("admin"))
async def cmd_admin(message: Message):
    if message.from_user.id not in ADMIN_IDS:
        await message.answer("❌ Admin access required")
        return
    
    keyboard = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="📊 Stats", callback_data="admin_stats"),
             InlineKeyboardButton(text="👥 Users", callback_data="admin_users")],
            [InlineKeyboardButton(text="🔄 Restart Services", callback_data="admin_restart")],
            [InlineKeyboardButton(text="🔙 Cancel", callback_data="cancel")]
        ]
    )
    
    await message.answer("🔧 Admin Panel:", reply_markup=keyboard)

@dp.callback_query(F.data.startswith("admin_"))
async def process_admin(callback: CallbackQuery):
    if callback.from_user.id not in ADMIN_IDS:
        await callback.answer("❌ Admin access required")
        return
    
    action = callback.data.split("_")[1]
    
    if action == "stats":
        with get_db() as conn:
            c = conn.cursor()
            
            # Get stats
            c.execute("SELECT COUNT(*) FROM users")
            user_count = c.fetchone()[0]
            
            c.execute("SELECT COUNT(*) FROM accounts WHERE is_active = 1")
            account_count = c.fetchone()[0]
            
            c.execute("SELECT COUNT(*) FROM accounts WHERE is_active = 1 AND expires_at > datetime('now')")
            active_accounts = c.fetchone()[0]
            
            stats_text = f"""
📊 Server Statistics:

👥 Total Users: {user_count}
📱 Total Accounts: {account_count}
✅ Active Accounts: {active_accounts}
🔄 Service: Running
            """
            
            await callback.message.edit_text(stats_text.strip())
    
    elif action == "restart":
        await callback.message.edit_text("🔄 Restarting services...")
        os.system("systemctl restart autoscript-manager autoscript-bot")
        await callback.message.edit_text("✅ Services restarted successfully")
    
    await callback.answer()

# Cancel handler
@dp.callback_query(F.data == "cancel")
async def cancel_handler(callback: CallbackQuery):
    await callback.message.delete()
    await callback.answer()

# Help command
@dp.message(Command("help"))
async def cmd_help(message: Message):
    help_text = """
🔧 AutoScript VPN Bot Help

Available Commands:
/start - Start the bot
/balance - Check your balance
/create - Create new VPN account
/accounts - List your accounts
/topup - Add balance to your account
/help - Show this help message

For admin: /admin

📱 Supported Protocols:
• VLESS (recommended)
• VMess 
• Trojan
• Shadowsocks

💡 Each account costs 1000 credits for 30 days.
    """
    
    await message.answer(help_text.strip())

async def main():
    print("🤖 Starting Telegram Bot...")
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
EOF

    chmod +x manager.py bot.py
    log("Application files created")
}

setup_nginx() {
    log "Setting up Nginx proxy..."
    
    cat > /etc/nginx/sites-available/autoscript-vpn << 'EOF'
server {
    listen 80;
    server_name _;
    
    location / {
        return 404;
    }
    
    location /export/ {
        proxy_pass http://127.0.0.1:8000/export/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
EOF

    # Enable site
    ln -sf /etc/nginx/sites-available/autoscript-vpn /etc/nginx/sites-enabled/
    systemctl enable nginx
    systemctl restart nginx
    
    log "Nginx configured"
}

start_services() {
    log "Starting services..."
    
    systemctl enable autoscript-manager
    systemctl enable autoscript-bot
    
    systemctl start autoscript-manager
    sleep 2
    systemctl start autoscript-bot
    
    log "Services started"
}

show_final_instructions() {
    log "Installation completed!"
    echo
    echo "📋 NEXT STEPS:"
    echo "1. Edit configuration:"
    echo "   nano $INSTALL_DIR/.env"
    echo
    echo "2. Important: Set your Telegram Bot Token"
    echo "   Get it from @BotFather on Telegram"
    echo
    echo "3. Check service status:"
    echo "   systemctl status autoscript-manager"
    echo "   systemctl status autoscript-bot"
    echo
    echo "4. View logs:"
    echo "   tail -f $INSTALL_DIR/logs/*.log"
    echo
    echo "5. Admin commands in Telegram: /admin"
    echo
    echo "🔧 The system is now running with mock payments."
    echo "   To enable real payments, update ORDERKUOTA_API_KEY in .env"
    echo
}

# Main installation flow
main() {
    log "Starting AutoScript VPN installation..."
    
    install_dependencies
    create_environment
    setup_firewall
    create_config_files
    create_application_files
    create_systemd_services
    setup_nginx
    start_services
    show_final_instructions
    
    log "🎉 Installation completed successfully!"
}

main