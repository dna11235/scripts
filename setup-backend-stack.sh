#!/bin/bash

# Development Stack Installation Script for Ubuntu Server 25.04
# Stack: Bun, Elysia, Drizzle, PostgreSQL, Caddy, JWT Authentication
# Author: Auto-generated setup script
# Date: $(date)

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   error "This script should not be run as root for security reasons."
   exit 1
fi

# Check Ubuntu version
if ! grep -q "Ubuntu" /etc/os-release; then
    error "This script is designed for Ubuntu systems only."
    exit 1
fi

log "Starting Development Stack Installation for Ubuntu Server 25.04"
log "Stack: Bun, Elysia, Drizzle, PostgreSQL, Caddy, JWT Authentication"

# Collect configuration information
echo ""
info "Please provide configuration details for your development stack:"
echo ""

# Database configuration
read -p "Enter PostgreSQL database name: " DB_NAME
read -p "Enter PostgreSQL username: " DB_USER
read -s -p "Enter PostgreSQL password: " DB_PASSWORD
echo ""
read -s -p "Confirm PostgreSQL password: " DB_PASSWORD_CONFIRM
echo ""

if [ "$DB_PASSWORD" != "$DB_PASSWORD_CONFIRM" ]; then
    error "Passwords do not match!"
    exit 1
fi

# Server configuration
read -p "Enter your server IP address (e.g., 192.168.1.100): " SERVER_IP
read -p "Enter server port for your application (default: 3000): " SERVER_PORT
SERVER_PORT=${SERVER_PORT:-3000}

# JWT configuration
read -p "Enter JWT secret key (leave empty to generate): " JWT_SECRET
if [ -z "$JWT_SECRET" ]; then
    JWT_SECRET=$(openssl rand -hex 32)
    info "Generated JWT secret: $JWT_SECRET"
fi

# Project configuration
read -p "Enter project directory name (default: my-server): " PROJECT_NAME
PROJECT_NAME=${PROJECT_NAME:-my-server}

echo ""
log "Configuration collected. Starting installation..."

# Update system
log "Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install essential packages
log "Installing essential packages..."
sudo apt install -y curl wget git build-essential software-properties-common \
    apt-transport-https ca-certificates gnupg lsb-release unzip jq

# Install Bun
log "Installing Bun..."
curl -fsSL https://bun.sh/install | bash
echo 'export PATH="$HOME/.bun/bin:$PATH"' >> ~/.bashrc
export PATH="$HOME/.bun/bin:$PATH"

# Verify Bun installation
if ! command -v bun &> /dev/null; then
    error "Bun installation failed!"
    exit 1
fi
log "Bun installed successfully: $(bun --version)"

# Install PostgreSQL
log "Installing PostgreSQL..."
sudo apt install -y postgresql postgresql-contrib postgresql-client

# Start and enable PostgreSQL
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Configure PostgreSQL
log "Configuring PostgreSQL..."
sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';"
sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"
sudo -u postgres psql -c "ALTER USER $DB_USER CREATEDB;"

# Configure PostgreSQL for remote connections (if needed)
sudo sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '*'/" /etc/postgresql/*/main/postgresql.conf
echo "host    all             all             0.0.0.0/0               md5" | sudo tee -a /etc/postgresql/*/main/pg_hba.conf

# Restart PostgreSQL
sudo systemctl restart postgresql

log "PostgreSQL configured successfully"

# Install Caddy
log "Installing Caddy..."
sudo apt install -y debian-keyring debian-archive-keyring
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update
sudo apt install -y caddy

# Start and enable Caddy
sudo systemctl start caddy
sudo systemctl enable caddy

log "Caddy installed successfully"

# Create project directory
log "Creating project directory..."
mkdir -p ~/$PROJECT_NAME
cd ~/$PROJECT_NAME

# Initialize Bun project
log "Initializing Bun project..."
bun init -y

# Install Elysia and other dependencies
log "Installing Elysia, Drizzle, and other dependencies..."
bun add elysia
bun add drizzle-orm postgres
bun add -d drizzle-kit
bun add @elysiajs/jwt @elysiajs/cors @elysiajs/helmet
bun add bcryptjs
bun add -d @types/bcryptjs

# Create basic project structure
log "Creating project structure..."
mkdir -p src/{routes,middleware,db,types}

# Create environment file
log "Creating environment configuration..."
cat > .env << EOF
# Database Configuration
DATABASE_URL="postgresql://$DB_USER:$DB_PASSWORD@localhost:5432/$DB_NAME"
DB_HOST=localhost
DB_PORT=5432
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASSWORD=$DB_PASSWORD

# Server Configuration
PORT=$SERVER_PORT
NODE_ENV=development

# JWT Configuration
JWT_SECRET=$JWT_SECRET

# Server Configuration
SERVER_IP=$SERVER_IP
EOF

# Create Drizzle configuration
log "Creating Drizzle configuration..."
cat > drizzle.config.ts << 'EOF'
import { defineConfig } from 'drizzle-kit';

export default defineConfig({
  schema: './src/db/schema.ts',
  out: './drizzle',
  dialect: 'postgresql',
  dbCredentials: {
    url: process.env.DATABASE_URL!,
  },
});
EOF

# Create database schema
log "Creating database schema..."
cat > src/db/schema.ts << 'EOF'
import { pgTable, serial, text, timestamp, boolean } from 'drizzle-orm/pg-core';

export const users = pgTable('users', {
  id: serial('id').primaryKey(),
  email: text('email').unique().notNull(),
  password: text('password').notNull(),
  name: text('name').notNull(),
  isActive: boolean('is_active').default(true),
  createdAt: timestamp('created_at').defaultNow(),
  updatedAt: timestamp('updated_at').defaultNow(),
});

export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;
EOF

# Create database connection
log "Creating database connection..."
cat > src/db/index.ts << 'EOF'
import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import * as schema from './schema';

const connectionString = process.env.DATABASE_URL!;
const client = postgres(connectionString);

export const db = drizzle(client, { schema });
EOF

# Create JWT middleware
log "Creating JWT middleware..."
cat > src/middleware/auth.ts << 'EOF'
import { Elysia } from 'elysia';
import { jwt } from '@elysiajs/jwt';

export const authMiddleware = new Elysia()
  .use(jwt({
    name: 'jwt',
    secret: process.env.JWT_SECRET!,
  }))
  .derive(async ({ jwt, cookie: { auth } }) => {
    const profile = await jwt.verify(auth.value);
    return {
      user: profile,
      isAuthenticated: !!profile,
    };
  });
EOF

# Create auth routes
log "Creating authentication routes..."
cat > src/routes/auth.ts << 'EOF'
import { Elysia, t } from 'elysia';
import { jwt } from '@elysiajs/jwt';
import bcrypt from 'bcryptjs';
import { db } from '../db';
import { users } from '../db/schema';
import { eq } from 'drizzle-orm';

export const authRoutes = new Elysia({ prefix: '/auth' })
  .use(jwt({
    name: 'jwt',
    secret: process.env.JWT_SECRET!,
  }))
  .post('/register', async ({ body, jwt, cookie: { auth } }) => {
    const { email, password, name } = body;
    
    // Check if user already exists
    const existingUser = await db.select().from(users).where(eq(users.email, email));
    if (existingUser.length > 0) {
      return { error: 'User already exists' };
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create user
    const newUser = await db.insert(users).values({
      email,
      password: hashedPassword,
      name,
    }).returning();
    
    // Generate JWT token
    const token = await jwt.sign({ userId: newUser[0].id, email: newUser[0].email });
    
    auth.set({
      value: token,
      httpOnly: true,
      maxAge: 7 * 86400, // 7 days
    });
    
    return { 
      message: 'User created successfully',
      user: {
        id: newUser[0].id,
        email: newUser[0].email,
        name: newUser[0].name,
      }
    };
  }, {
    body: t.Object({
      email: t.String(),
      password: t.String(),
      name: t.String(),
    }),
  })
  .post('/login', async ({ body, jwt, cookie: { auth } }) => {
    const { email, password } = body;
    
    // Find user
    const user = await db.select().from(users).where(eq(users.email, email));
    if (user.length === 0) {
      return { error: 'Invalid credentials' };
    }
    
    // Verify password
    const isValidPassword = await bcrypt.compare(password, user[0].password);
    if (!isValidPassword) {
      return { error: 'Invalid credentials' };
    }
    
    // Generate JWT token
    const token = await jwt.sign({ userId: user[0].id, email: user[0].email });
    
    auth.set({
      value: token,
      httpOnly: true,
      maxAge: 7 * 86400, // 7 days
    });
    
    return { 
      message: 'Login successful',
      user: {
        id: user[0].id,
        email: user[0].email,
        name: user[0].name,
      }
    };
  }, {
    body: t.Object({
      email: t.String(),
      password: t.String(),
    }),
  })
  .post('/logout', ({ cookie: { auth } }) => {
    auth.remove();
    return { message: 'Logged out successfully' };
  });
EOF

# Create main server file
log "Creating main server file..."
cat > src/index.ts << 'EOF'
import { Elysia } from 'elysia';
import { cors } from '@elysiajs/cors';
import { helmet } from '@elysiajs/helmet';
import { authRoutes } from './routes/auth';
import { authMiddleware } from './middleware/auth';

const app = new Elysia()
  .use(cors())
  .use(helmet())
  .use(authRoutes)
  .get('/', () => ({
    message: 'Server is running!',
    timestamp: new Date().toISOString(),
  }))
  .get('/protected', ({ user, isAuthenticated }) => {
    if (!isAuthenticated) {
      return { error: 'Unauthorized' };
    }
    return { 
      message: 'This is a protected route',
      user 
    };
  }, {
    beforeHandle: authMiddleware,
  })
  .listen(process.env.PORT || 3000);

console.log(`🦊 Elysia is running at http://localhost:${app.server?.port}`);
EOF

# Update package.json scripts
log "Updating package.json scripts..."
cat > package.json << EOF
{
  "name": "$PROJECT_NAME",
  "module": "src/index.ts",
  "type": "module",
  "scripts": {
    "dev": "bun run --watch src/index.ts",
    "start": "bun run src/index.ts",
    "db:generate": "drizzle-kit generate",
    "db:push": "drizzle-kit push",
    "db:studio": "drizzle-kit studio",
    "build": "bun build src/index.ts --outdir ./dist --target node",
    "lint": "eslint src --ext .ts",
    "test": "bun test"
  },
  "dependencies": {
    "elysia": "latest",
    "drizzle-orm": "latest",
    "postgres": "latest",
    "@elysiajs/jwt": "latest",
    "@elysiajs/cors": "latest",
    "@elysiajs/helmet": "latest",
    "bcryptjs": "latest"
  },
  "devDependencies": {
    "drizzle-kit": "latest",
    "@types/bcryptjs": "latest",
    "bun-types": "latest"
  }
}
EOF

# Install dependencies
log "Installing project dependencies..."
bun install

# Generate and push database schema
log "Setting up database schema..."
bun run db:generate
bun run db:push

# Create Caddy configuration
log "Creating Caddy configuration..."
sudo tee /etc/caddy/Caddyfile > /dev/null << EOF
:80 {
    reverse_proxy localhost:$SERVER_PORT
    encode gzip
    
    # Security headers
    header {
        X-Frame-Options DENY
        X-Content-Type-Options nosniff
        X-XSS-Protection "1; mode=block"
        Referrer-Policy strict-origin-when-cross-origin
        X-Permitted-Cross-Domain-Policies none
        Permissions-Policy "geolocation=(), microphone=(), camera=()"
    }
}
EOF

# Reload Caddy configuration
sudo systemctl reload caddy

# Create systemd service for the application
log "Creating systemd service..."
sudo tee /etc/systemd/system/$PROJECT_NAME.service > /dev/null << EOF
[Unit]
Description=$PROJECT_NAME Server
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=/home/$USER/$PROJECT_NAME
ExecStart=/home/$USER/.bun/bin/bun run src/index.ts
Restart=always
RestartSec=10
Environment=NODE_ENV=production
EnvironmentFile=/home/$USER/$PROJECT_NAME/.env

[Install]
WantedBy=multi-user.target
EOF

# Enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable $PROJECT_NAME
sudo systemctl start $PROJECT_NAME

# Configure firewall
log "Configuring firewall..."
sudo ufw allow ssh
sudo ufw allow 80
sudo ufw --force enable

# Create a simple test script
log "Creating test script..."
cat > test-api.sh << 'EOF'
#!/bin/bash

echo "Testing API endpoints..."

# Test health endpoint
echo "1. Testing health endpoint (localhost):"
curl -s http://localhost:$SERVER_PORT/ | jq .

echo -e "\n2. Testing health endpoint (external IP):"
curl -s http://$SERVER_IP/ | jq .

echo -e "\n3. Testing registration:"
curl -s -X POST http://localhost:$SERVER_PORT/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123","name":"Test User"}' | jq .

echo -e "\n4. Testing login:"
curl -s -X POST http://localhost:$SERVER_PORT/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}' | jq .

echo -e "\nAPI tests completed!"
EOF

chmod +x test-api.sh

# Final setup summary
log "Installation completed successfully!"
echo ""
info "=== INSTALLATION SUMMARY ==="
info "✅ Ubuntu system updated"
info "✅ Bun installed and configured (no Node.js dependency)"
info "✅ PostgreSQL installed and configured"
info "✅ Database '$DB_NAME' created with user '$DB_USER'"
info "✅ Caddy web server installed and configured (HTTP only)"
info "✅ Elysia application created in ~/$PROJECT_NAME"
info "✅ JWT authentication configured"
info "✅ Drizzle ORM configured"
info "✅ Systemd service created and started"
info "✅ Firewall configured (SSH + HTTP)"
echo ""
info "=== CONFIGURATION ==="
info "Project Directory: ~/$PROJECT_NAME"
info "Database: $DB_NAME"
info "Server Port: $SERVER_PORT"
info "Server IP: $SERVER_IP"
info "Service: $PROJECT_NAME.service"
echo ""
info "=== NEXT STEPS ==="
info "1. Check service status: sudo systemctl status $PROJECT_NAME"
info "2. View logs: sudo journalctl -u $PROJECT_NAME -f"
info "3. Test API: cd ~/$PROJECT_NAME && ./test-api.sh"
info "4. Access your app: http://$SERVER_IP/"
info "5. Database studio: cd ~/$PROJECT_NAME && bun run db:studio"
echo ""
info "=== IMPORTANT FILES ==="
info "• Environment variables: ~/$PROJECT_NAME/.env"
info "• Caddy config: /etc/caddy/Caddyfile"
info "• Service file: /etc/systemd/system/$PROJECT_NAME.service"
info "• Application logs: sudo journalctl -u $PROJECT_NAME"
echo ""
warn "Remember to:"
warn "• Keep your .env file secure and never commit it to version control"
warn "• Change default passwords in production"
warn "• Consider adding SSL/TLS if exposing to internet"
warn "• Set up regular database backups"
warn "• Monitor your application logs"
warn "• This setup uses HTTP only - suitable for internal/development use"
echo ""
log "Your development stack is ready! 🚀"
