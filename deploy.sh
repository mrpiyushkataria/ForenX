#!/bin/bash

set -e  # Exit on error

echo "🚀 ForenX Sentinel Deployment Script"
echo "===================================="

# Configuration
ENV=${1:-production}
DOCKER_REGISTRY="your-registry.com"
VERSION="1.0.0"
APP_NAME="forenx-sentinel"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_dependencies() {
    log_info "Checking dependencies..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        log_error "Docker Compose is not installed"
        exit 1
    fi
    
    # Check required ports
    for port in 8000 3000 5432 6379; do
        if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null ; then
            log_warn "Port $port is already in use"
        fi
    done
    
    log_info "Dependencies check passed"
}

setup_environment() {
    log_info "Setting up $ENV environment..."
    
    # Create environment file if it doesn't exist
    if [ ! -f .env ]; then
        log_warn ".env file not found, creating from template..."
        cp .env.example .env
        
        # Generate secure secrets
        if [ "$ENV" = "production" ]; then
            sed -i "s/SECRET_KEY=.*/SECRET_KEY=$(openssl rand -hex 32)/" .env
            sed -i "s/DB_PASSWORD=.*/DB_PASSWORD=$(openssl rand -hex 16)/" .env
            sed -i "s/GRAFANA_PASSWORD=.*/GRAFANA_PASSWORD=$(openssl rand -hex 16)/" .env
        fi
        
        log_warn "Please edit .env file with your configuration"
        read -p "Press enter to continue after editing .env file..."
    fi
    
    # Load environment variables
    export $(grep -v '^#' .env | xargs)
    
    # Create required directories
    mkdir -p {logs,uploads,monitoring/prometheus,monitoring/grafana}
    
    log_info "Environment setup completed"
}

build_images() {
    log_info "Building Docker images..."
    
    # Build API image
    log_info "Building API image..."
    docker build -t $DOCKER_REGISTRY/$APP_NAME-api:$VERSION -f backend/Dockerfile backend/
    
    # Build Frontend image
    log_info "Building Frontend image..."
    docker build -t $DOCKER_REGISTRY/$APP_NAME-frontend:$VERSION -f frontend/Dockerfile frontend/
    
    # Build Worker image
    log_info "Building Worker image..."
    docker build -t $DOCKER_REGISTRY/$APP_NAME-worker:$VERSION -f backend/Dockerfile.worker backend/
    
    # Push to registry if in production
    if [ "$ENV" = "production" ]; then
        log_info "Pushing images to registry..."
        docker push $DOCKER_REGISTRY/$APP_NAME-api:$VERSION
        docker push $DOCKER_REGISTRY/$APP_NAME-frontend:$VERSION
        docker push $DOCKER_REGISTRY/$APP_NAME-worker:$VERSION
    fi
    
    log_info "Images built successfully"
}

run_migrations() {
    log_info "Running database migrations..."
    
    # Wait for PostgreSQL to be ready
    log_info "Waiting for PostgreSQL..."
    until docker-compose exec -T postgres pg_isready -U $POSTGRES_USER; do
        sleep 2
    done
    
    # Run Alembic migrations
    docker-compose exec -T api alembic upgrade head
    
    # Create default data
    docker-compose exec -T api python -c "
from app.database import SessionLocal
from app.models import User, Role, Permission
from app.auth import AuthService

db = SessionLocal()

# Create default roles
roles = ['admin', 'analyst', 'viewer']
for role_name in roles:
    if not db.query(Role).filter(Role.name == role_name).first():
        role = Role(name=role_name, description=f'{role_name.capitalize()} role')
        db.add(role)

db.commit()
print('Default roles created')
"
    
    log_info "Migrations completed"
}

start_services() {
    log_info "Starting services..."
    
    # Stop existing services
    docker-compose down
    
    # Start services
    docker-compose up -d
    
    # Wait for services to be healthy
    log_info "Waiting for services to be healthy..."
    sleep 10
    
    # Check service health
    services=("api" "frontend" "postgres" "redis")
    for service in "${services[@]}"; do
        if docker-compose ps $service | grep -q "Up"; then
            log_info "$service is running"
        else
            log_error "$service failed to start"
            docker-compose logs $service
            exit 1
        fi
    done
    
    log_info "All services started successfully"
}

run_tests() {
    log_info "Running tests..."
    
    # Run backend tests
    docker-compose exec -T api python -m pytest tests/ -v
    
    # Run frontend tests if available
    if [ -d "frontend" ]; then
        docker-compose exec -T frontend npm test -- --passWithNoTests
    fi
    
    log_info "Tests completed"
}

setup_monitoring() {
    log_info "Setting up monitoring..."
    
    # Create Prometheus configuration
    cat > monitoring/prometheus/prometheus.yml << EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'forenx-api'
    static_configs:
      - targets: ['api:8000']
    
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']
    
  - job_name: 'postgres-exporter'
    static_configs:
      - targets: ['postgres-exporter:9187']
    
  - job_name: 'redis-exporter'
    static_configs:
      - targets: ['redis-exporter:9121']
EOF
    
    # Import Grafana dashboards
    if [ ! -d "monitoring/grafana/dashboards" ]; then
        mkdir -p monitoring/grafana/dashboards
        # Download default dashboards
        curl -o monitoring/grafana/dashboards/forenx-overview.json \
             https://raw.githubusercontent.com/grafana/grafana/main/public/dashboards/overview.json
    fi
    
    log_info "Monitoring setup completed"
}

create_backup() {
    log_info "Creating backup..."
    
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    BACKUP_DIR="backups/$TIMESTAMP"
    
    mkdir -p $BACKUP_DIR
    
    # Backup database
    log_info "Backing up database..."
    docker-compose exec -T postgres pg_dump -U $POSTGRES_USER $POSTGRES_DB > $BACKUP_DIR/database.sql
    
    # Backup uploads
    log_info "Backing up uploads..."
    cp -r uploads $BACKUP_DIR/
    
    # Backup logs
    log_info "Backing up logs..."
    cp -r logs $BACKUP_DIR/
    
    # Create backup archive
    tar -czf backups/forenx-backup-$TIMESTAMP.tar.gz $BACKUP_DIR
    
    # Cleanup
    rm -rf $BACKUP_DIR
    
    log_info "Backup created: backups/forenx-backup-$TIMESTAMP.tar.gz"
}

show_status() {
    log_info "Deployment Status"
    echo "=================="
    
    # Show running containers
    echo ""
    echo "Running Containers:"
    docker-compose ps
    
    # Show API health
    echo ""
    echo "API Health:"
    curl -s http://localhost:8000/health | jq . || echo "API not responding"
    
    # Show URLs
    echo ""
    echo "Application URLs:"
    echo "Frontend: http://localhost:3000"
    echo "API: http://localhost:8000"
    echo "API Documentation: http://localhost:8000/docs"
    echo "Grafana: http://localhost:3001 (admin/$GRAFANA_PASSWORD)"
    echo "Prometheus: http://localhost:9090"
    
    # Show logs
    echo ""
    echo "Recent Logs:"
    docker-compose logs --tail=10 api
}

main() {
    log_info "Starting ForenX Sentinel deployment"
    
    case "$ENV" in
        "development")
            log_info "Deploying in development mode"
            ;;
        "production")
            log_info "Deploying in production mode"
            ;;
        *)
            log_error "Unknown environment: $ENV"
            exit 1
            ;;
    esac
    
    # Execute deployment steps
    check_dependencies
    setup_environment
    build_images
    start_services
    run_migrations
    setup_monitoring
    
    if [ "$ENV" = "production" ]; then
        run_tests
        create_backup
    fi
    
    show_status
    
    log_info "🎉 Deployment completed successfully!"
    log_info "ForenX Sentinel is now running"
}

# Run main function
main "$@"
