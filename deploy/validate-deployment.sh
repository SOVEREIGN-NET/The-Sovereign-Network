#!/bin/bash
# Quick validation of ZHTP deployment system

echo "🔍 ZHTP Deployment System Validation"
echo "====================================="

# Check if we're in the right directory
if [ ! -f "docker-compose.full-test.yml" ]; then
    echo "❌ Not in deployment directory"
    exit 1
fi

# Validate Docker Compose file
echo "Validating Docker Compose configuration..."
if docker-compose -f docker-compose.full-test.yml config --quiet; then
    echo "✅ Docker Compose configuration is valid"
else
    echo "❌ Docker Compose configuration has errors"
    exit 1
fi

# Check if test scripts are executable
echo "Checking test scripts..."
if [ -f "test-scripts/run-full-tests.sh" ]; then
    echo "✅ Main test script exists"
else
    echo "❌ Main test script missing"
    exit 1
fi

# Check if Dockerfile exists
if [ -f "Dockerfile" ] && [ -f "Dockerfile.test" ]; then
    echo "✅ Dockerfiles exist"
else
    echo "❌ Dockerfiles missing"
    exit 1
fi

# Check if config files exist
if [ -d "docker-config" ] && [ -f "docker-config/ceremony.json" ]; then
    echo "✅ Configuration files exist"
else
    echo "❌ Configuration files missing"
    exit 1
fi

# Test Docker connectivity
echo "Testing Docker connectivity..."
if docker info > /dev/null 2>&1; then
    echo "✅ Docker daemon is running"
else
    echo "❌ Docker daemon is not accessible"
    exit 1
fi

# Estimate resource requirements
echo ""
echo "📊 Resource Requirements:"
echo "- RAM: 8GB+ recommended"
echo "- Disk: 20GB+ free space"
echo "- CPU: 4+ cores recommended"
echo "- Network: Internet connection for image pulls"

echo ""
echo "🚀 Deployment System Ready!"
echo "Run './deploy-complete-system.sh' to start full deployment"
echo "Or run './deploy-complete-system.bat' on Windows"
