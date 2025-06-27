@echo off
REM ZHTP Cross-Machine Messaging Test
REM This script tests the complete Whisper.zhtp messaging system

echo ========================================
echo ZHTP Cross-Machine Messaging Test
echo ========================================
echo.

echo 🔍 Testing ZHTP API endpoints...

REM Test API status
echo.
echo 📡 Checking ZHTP network status...
curl -s http://localhost:8000/api/status
echo.

REM Test DNS resolution
echo.
echo 🌐 Testing DNS resolution for whisper.zhtp...
curl -s "http://localhost:8000/api/dns/resolve?domain=whisper.zhtp"
echo.

REM Test message sending
echo.
echo 💬 Testing message sending API...
curl -X POST -H "Content-Type: application/json" -d "{\"message\":\"Hello from cross-machine test!\",\"target\":\"bootstrap-node\",\"zk_identity\":\"test_user_001\"}" http://localhost:8000/api/messages/send
echo.

REM Test message inbox
echo.
echo 📥 Testing message inbox...
curl -s http://localhost:8000/api/messages/inbox
echo.

echo.
echo ✅ API tests completed!
echo.
echo 🌐 Open your browser and go to:
echo    http://localhost:8000           (Welcome/Onboarding)
echo    http://localhost:8000/browser   (Main ZHTP Browser)
echo    http://localhost:8000/whisper   (Whisper Messaging)
echo.
echo 🧪 For cross-machine testing:
echo 1. Run this ZHTP node on Computer A
echo 2. Run another ZHTP node on Computer B  
echo 3. Use Whisper to send messages between them
echo 4. Messages should route through the ZHTP network!
echo.
pause
