# AutoFlow Backend

Production-ready Node.js backend for AutoFlow Studio automation tool.

## 🚀 Features

- **Secure Authentication**: JWT with refresh token rotation, bcrypt password hashing
- **Workflow Management**: Create, update, delete, and execute workflows with graph-based validation
- **Real-time Execution**: WebSocket-based live logging and status updates
- **Job Queue**: Redis-backed BullMQ for reliable workflow execution
- **Type Safety**: Full TypeScript support with strict type checking
- **API Documentation**: Auto-generated Swagger/OpenAPI specifications
- **Security**: Rate limiting, CORS, Helmet headers, input validation
- **Database**: PostgreSQL with proper indexing and migrations
- **Logging**: Structured JSON logging with Winston
- **Docker Ready**: Multi-stage Docker builds with health checks

## 🛠️ Tech Stack

- **Runtime**: Node.js 20+ with TypeScript
- **Framework**: Express.js with async/await
- **Database**: PostgreSQL with Kysely ORM
- **Queue**: Redis with BullMQ
- **Real-time**: Socket.IO
- **Validation**: Zod schemas
- **Authentication**: JWT with bcrypt
- **Documentation**: Swagger/OpenAPI
- **Testing**: Vitest with testcontainers
- **Logging**: Winston

## 📋 Prerequisites

- Node.js 20+
- PostgreSQL 13+
- Redis 6+
- npm 9+

## 🚀 Quick Start

### 1. Clone and Install

```bash
git clone <repository-url>
cd backend
npm install
```

### 2. Environment Setup

Copy the example environment file:

```bash
cp .env.example .env
```

Update the environment variables with your configuration:

```env
# Database
DATABASE_URL=postgresql://postgres:password@localhost:5432/autoflow
REDIS_URL=redis://localhost:6379

# Authentication (CHANGE IN PRODUCTION!)
JWT_SECRET=your-super-secret-jwt-key-change-in-production-32-chars-min
CRYPTO_SECRET=your-32-char-encryption-key-change-in-production

# Server
PORT=3001
NODE_ENV=development
FRONTEND_URL=http://localhost:5173
```

### 3. Database Setup

```bash
# Start PostgreSQL and Redis (using Docker)
npm run docker:dev

# Run migrations
npm run migrate

# Seed with sample data (optional)
npm run seed
```

### 4. Start Development Server

```bash
npm run dev
```

The server will be available at `http://localhost:3001`

## 🔧 Development

### Available Scripts

- `npm run dev` - Start development server with hot reload
- `npm run build` - Build for production
- `npm run start` - Start production server
- `npm test` - Run tests
- `npm run lint` - Run ESLint
- `npm run lint:fix` - Fix ESLint issues
- `npm run format` - Format code with Prettier
- `npm run migrate` - Run database migrations
- `npm run seed` - Seed database with test data

### Docker Development

```bash
# Start all services (PostgreSQL, Redis, Backend)
npm run docker:dev

# Stop services
npm run docker:dev:down

# Build production Docker image
npm run docker:build

# Run production container
npm run docker:run
```

## 🏗️ API Documentation

When running in development mode, interactive API documentation is available at:

```
http://localhost:3001/api/docs
```

### Key Endpoints

#### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - User login
- `POST /api/auth/refresh` - Refresh access token
- `GET /api/auth/me` - Get current user profile
- `POST /api/auth/logout` - Logout user

#### Workflows
- `GET /api/workflows` - List user workflows (paginated)
- `POST /api/workflows` - Create new workflow
- `GET /api/workflows/:id` - Get workflow details
- `PUT /api/workflows/:id` - Update workflow
- `DELETE /api/workflows/:id` - Delete workflow
- `POST /api/workflows/:id/duplicate` - Duplicate workflow
- `POST /api/workflows/:id/execute` - Execute workflow
- `GET /api/workflows/:id/stats` - Get workflow statistics

#### Executions
- `GET /api/executions` - List executions (filtered by workflow)
- `GET /api/executions/:id` - Get execution details
- `GET /api/executions/:id/logs` - Get execution logs
- `POST /api/executions/:id/retry` - Retry failed execution
- `POST /api/executions/:id/cancel` - Cancel running execution

#### Health & Info
- `GET /health` - Health check endpoint
- `GET /api` - API information

## 🔌 WebSocket Events

Connect to WebSocket at `ws://localhost:3001` with JWT token for real-time updates.

### Client Events
- `subscribe:execution` - Subscribe to execution logs
- `subscribe:workflow` - Subscribe to workflow updates
- `unsubscribe:execution` - Unsubscribe from execution
- `unsubscribe:workflow` - Unsubscribe from workflow
- `ping` - Connection health check

### Server Events
- `connected` - Connection established
- `subscription:confirmed` - Subscription confirmed
- `execution:logs` - Real-time execution logs
- `execution:status` - Execution status updates
- `execution:complete` - Execution completed
- `workflow:update` - Workflow updates
- `notification` - User notifications
- `pong` - Ping response

## 🗄️ Database Schema

### Tables
- **users** - User accounts with authentication data
- **workflows** - Workflow definitions with graph data (JSONB)
- **executions** - Execution history and status tracking
- **api_keys** - Scoped API keys for integrations

### Key Features
- UUID primary keys
- JSONB for flexible graph storage
- Proper indexing for performance
- Foreign key constraints
- Timestamps with triggers

## 🧪 Testing

```bash
# Run unit and integration tests
npm test

# Run with coverage
npm run test:coverage

# Run specific test file
npm test auth.test.ts
```

### Test Structure
- Unit tests for individual services
- Integration tests for API endpoints
- E2E tests for workflow execution
- Testcontainers for database testing

## 🚢 Deployment

### Environment Variables (Production)

```env
NODE_ENV=production
DATABASE_URL=postgresql://user:pass@prod-db:5432/autoflow
REDIS_URL=redis://prod-redis:6379
JWT_SECRET=prod-jwt-secret-32-chars-min
CRYPTO_SECRET=prod-crypto-secret-32-chars-min
FRONTEND_URL=https://your-domain.com
LOG_LEVEL=warn
```

### Docker Production

```bash
# Build image
docker build -t autoflow-backend:latest .

# Run container
docker run -d \
  --name autoflow-backend \
  -p 3001:3001 \
  -e NODE_ENV=production \
  -e DATABASE_URL=postgresql://... \
  -e REDIS_URL=redis://... \
  -e JWT_SECRET=... \
  -e CRYPTO_SECRET=... \
  autoflow-backend:latest
```

### Health Checks

The service includes built-in health checks:
- Database connectivity
- Redis connectivity
- Queue status
- Memory usage

Access health status at `/health`

## 🔒 Security

- **Authentication**: JWT tokens with 15-minute expiry
- **Authorization**: Role-based access control
- **Rate Limiting**: 100 requests per 15 minutes per IP
- **Input Validation**: Zod schemas for all inputs
- **SQL Injection**: Parameterized queries via Kysely
- **XSS Protection**: Helmet.js security headers
- **CORS**: Configurable origin whitelist
- **Password Security**: bcrypt with 12 rounds

## 📊 Monitoring

### Logging
- Structured JSON logging
- Request/response logging
- Error tracking with stack traces
- Performance metrics

### Metrics Available
- API response times
- Database query performance
- Queue processing rates
- WebSocket connection counts
- Memory and CPU usage

## 🤝 Contributing

Please see [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## 📝 License

MIT License - see [LICENSE](LICENSE) for details.

## 🆘 Support

- Documentation: `/api/docs` (dev only)
- Health Check: `/health`
- API Info: `/api`

For issues and questions, please refer to the project documentation or create an issue in the repository.