import pytest
import json
from datetime import datetime, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.database import Base, get_db
from app.models import LogEvent, User, Alert
from app.auth import AuthService
from app.analysis.sql_injection import SQLInjectionDetector
from app.analysis.xss_detector import XSSDetector
from app.analysis.brute_force import BruteForceDetector
from app.analysis.correlation import ForensicCorrelationEngine

# Test database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Override get_db dependency
def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

client = TestClient(app)

# Test data
TEST_LOGS = [
    '192.168.1.100 - - [30/Dec/2025:10:00:00 +0000] "GET /api/users HTTP/1.1" 200 1234',
    '192.168.1.100 - - [30/Dec/2025:10:00:01 +0000] "GET /api/users?q=admin\' OR \'1\'=\'1 HTTP/1.1" 500 0',
    '192.168.1.100 - - [30/Dec/2025:10:00:02 +0000] "GET /wp-login.php HTTP/1.1" 404 0',
    '10.0.0.50 - - [30/Dec/2025:10:00:03 +0000] "POST /api/login HTTP/1.1" 401 0',
    '10.0.0.50 - - [30/Dec/2025:10:00:04 +0000] "POST /api/login HTTP/1.1" 401 0',
    '10.0.0.50 - - [30/Dec/2025:10:00:05 +0000] "POST /api/login HTTP/1.1" 401 0',
]

class TestForenXSystem:
    """Complete test suite for ForenX Sentinel"""
    
    def setup_method(self):
        """Setup test database"""
        Base.metadata.create_all(bind=engine)
        self.db = TestingSessionLocal()
        
        # Create test user
        self.test_user = User(
            username="testuser",
            email="test@example.com",
            hashed_password=AuthService.get_password_hash("testpassword"),
            is_active=True
        )
        self.db.add(self.test_user)
        self.db.commit()
    
    def teardown_method(self):
        """Cleanup test database"""
        self.db.close()
        Base.metadata.drop_all(bind=engine)
    
    def test_authentication(self):
        """Test authentication system"""
        # Register new user
        register_data = {
            "username": "newuser",
            "email": "new@example.com",
            "password": "SecurePass123!",
            "full_name": "Test User"
        }
        
        response = client.post("/api/auth/register", json=register_data)
        assert response.status_code == 200
        assert response.json()["username"] == "newuser"
        
        # Login
        login_data = {
            "username": "newuser",
            "password": "SecurePass123!"
        }
        
        response = client.post("/api/auth/login", data=login_data)
        assert response.status_code == 200
        assert "access_token" in response.json()
        
        token = response.json()["access_token"]
        
        # Access protected endpoint
        headers = {"Authorization": f"Bearer {token}"}
        response = client.get("/api/auth/me", headers=headers)
        assert response.status_code == 200
        assert response.json()["username"] == "newuser"
    
    def test_log_ingestion(self):
        """Test log ingestion and parsing"""
        # Upload test logs
        files = {"file": ("test.log", "\n".join(TEST_LOGS), "text/plain")}
        response = client.post("/api/upload/?log_type=nginx", files=files)
        
        assert response.status_code == 200
        assert response.json()["events_ingested"] == len(TEST_LOGS)
        
        # Verify events in database
        events = self.db.query(LogEvent).all()
        assert len(events) == len(TEST_LOGS)
        
        # Check parsed data
        sql_event = self.db.query(LogEvent).filter(
            LogEvent.payload.contains("OR")
        ).first()
        assert sql_event is not None
        assert sql_event.status == 500
    
    def test_sql_injection_detection(self):
        """Test SQL injection detection"""
        # Create test events with SQLi attempts
        events = [
            LogEvent(
                timestamp=datetime.utcnow(),
                source="nginx",
                ip="192.168.1.100",
                endpoint="/api/users",
                payload="q=admin' OR '1'='1",
                raw="SQL injection attempt",
                risk_score=0
            ),
            LogEvent(
                timestamp=datetime.utcnow(),
                source="nginx",
                ip="192.168.1.100",
                endpoint="/api/products",
                payload="id=1 UNION SELECT * FROM users",
                raw="UNION based SQLi",
                risk_score=0
            )
        ]
        
        for event in events:
            self.db.add(event)
        self.db.commit()
        
        # Test SQLi detector
        detector = SQLInjectionDetector()
        findings = detector.detect_in_events(self.db, hours=1)
        
        assert len(findings) >= 1
        assert findings[0]["risk_score"] > 50
        
        # Test specific pattern detection
        payload = "admin' OR '1'='1"
        score, patterns = detector.analyze_payload(payload)
        assert score >= 60
        assert len(patterns) > 0
    
    def test_xss_detection(self):
        """Test XSS detection"""
        detector = XSSDetector()
        
        # Test various XSS payloads
        test_payloads = [
            ("<script>alert('XSS')</script>", 70, ["basic_script"]),
            ("javascript:alert('XSS')", 60, ["basic_script"]),
            ("<img src=x onerror=alert('XSS')>", 80, ["event_handlers", "svg_xss"]),
            ("<svg/onload=alert('XSS')>", 75, ["svg_xss", "event_handlers"])
        ]
        
        for payload, expected_score, expected_patterns in test_payloads:
            score, patterns, context = detector.analyze_payload(payload, "/api/comments")
            assert score >= expected_score - 10  # Allow some variance
            assert any(p in str(patterns) for p in expected_patterns)
    
    def test_brute_force_detection(self):
        """Test brute force detection"""
        detector = BruteForceDetector()
        
        # Create failed login attempts
        for i in range(15):
            event = LogEvent(
                timestamp=datetime.utcnow() - timedelta(seconds=i*10),
                source="nginx",
                ip="10.0.0.50",
                endpoint="/api/login",
                method="POST",
                status=401,
                payload=f"username=admin&password=wrong{i}",
                raw=f"Failed login attempt {i}",
                risk_score=0
            )
            self.db.add(event)
        
        self.db.commit()
        
        # Test credential stuffing detection
        findings = detector.detect_credential_stuffing(self.db, hours=1)
        
        assert len(findings) > 0
        assert findings[0]["attack_type"] == "credential_stuffing"
        assert findings[0]["attempts"] >= 10
    
    def test_correlation_engine(self):
        """Test correlation engine"""
        correlation_engine = ForensicCorrelationEngine()
        
        # Create correlated events
        events = [
            # Web request
            LogEvent(
                timestamp=datetime.utcnow() - timedelta(seconds=5),
                source="nginx",
                ip="192.168.1.100",
                endpoint="/api/users",
                method="GET",
                status=200,
                payload="",
                raw="Web request",
                risk_score=20
            ),
            # Application error
            LogEvent(
                timestamp=datetime.utcnow() - timedelta(seconds=4),
                source="php",
                ip="192.168.1.100",
                endpoint="/api/users",
                method="GET",
                status=500,
                payload="SQL syntax error",
                raw="Application error",
                risk_score=60
            ),
            # Database query
            LogEvent(
                timestamp=datetime.utcnow() - timedelta(seconds=3),
                source="mysql",
                ip="192.168.1.100",
                endpoint=None,
                method="QUERY",
                status=None,
                payload="SELECT * FROM users WHERE id = 'admin' OR '1'='1'",
                raw="Database query",
                risk_score=70
            )
        ]
        
        for event in events:
            self.db.add(event)
        self.db.commit()
        
        # Test correlation
        start_time = datetime.utcnow() - timedelta(minutes=10)
        end_time = datetime.utcnow()
        
        chains = correlation_engine.correlate_attack_chain(
            self.db, start_time, end_time
        )
        
        assert len(chains) > 0
        assert chains[0]["confidence"] > 0.3
        assert len(chains[0]["timeline"]) >= 2
    
    def test_data_exfiltration_detection(self):
        """Test data exfiltration detection"""
        from app.analysis.data_exfiltration import DataExfiltrationDetector
        
        detector = DataExfiltrationDetector()
        
        # Create large data transfer events
        for i in range(100):
            event = LogEvent(
                timestamp=datetime.utcnow() - timedelta(minutes=i),
                source="nginx",
                ip="192.168.1.100",
                endpoint="/api/export/users",
                method="GET",
                status=200,
                response_size=1024 * 1024,  # 1MB each
                payload="",
                raw=f"Export request {i}",
                risk_score=0
            )
            self.db.add(event)
        
        self.db.commit()
        
        # Test detection
        findings = detector.detect_large_data_transfers(self.db, hours=24)
        
        assert len(findings) > 0
        assert findings[0]["total_mb"] > 50  # >50MB total
        assert findings[0]["is_export_endpoint"] == True
    
    def test_risk_scoring(self):
        """Test risk scoring engine"""
        from app.analysis.risk_scoring import AdvancedRiskScorer, RiskFactors
        
        scorer = AdvancedRiskScorer()
        
        # Create risk factors
        factors = RiskFactors(
            request_count=5000,
            error_count=1000,
            data_volume=500 * 1024 * 1024,  # 500MB
            unique_endpoints=200,
            unique_ips=50,
            requests_per_second=10.5,
            sql_injection_attempts=25,
            xss_attempts=15,
            is_sensitive_endpoint=True,
            ip_reputation_score=75.0,
            is_tor_exit_node=True,
            failed_logins=45,
            successful_logins=5
        )
        
        # Calculate risk
        score, level, breakdown = scorer.calculate_comprehensive_risk(factors)
        
        assert score >= 70  # Should be high risk
        assert level.name in ["HIGH", "CRITICAL"]
        assert "components" in breakdown
        assert "key_factors" in breakdown
        
        # Test reporting
        report = scorer.generate_risk_assessment_report(
            score, level, breakdown, "IP", "192.168.1.100"
        )
        
        assert "executive_summary" in report
        assert "recommendations" in report
        assert report["executive_summary"]["risk_score"] == score
    
    def test_api_endpoints(self):
        """Test API endpoints"""
        # Test health endpoint
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"
        
        # Test stats endpoint
        response = client.get("/api/stats/")
        assert response.status_code == 200
        assert "total_events" in response.json()
        
        # Test endpoints analysis
        response = client.get("/api/endpoints/?limit=10")
        assert response.status_code == 200
        assert isinstance(response.json(), list)
        
        # Test IP analysis
        response = client.get("/api/ips/?limit=10")
        assert response.status_code == 200
        assert isinstance(response.json(), list)
    
    def test_alert_system(self):
        """Test alert system"""
        from app.api.alerts import AlertManager
        
        alert_manager = AlertManager()
        
        # Create alert
        alert = alert_manager.create_alert(
            db=self.db,
            title="Test Alert",
            description="This is a test alert",
            severity="high",
            source="test_suite",
            metadata={"test": True, "source_ip": "192.168.1.100"}
        )
        
        assert alert.id is not None
        assert alert.severity == "high"
        assert alert.is_acknowledged == False
        
        # Test alert retrieval
        alerts = self.db.query(Alert).all()
        assert len(alerts) > 0
        
        # Test alert acknowledgment
        alert.is_acknowledged = True
        alert.acknowledged_at = datetime.utcnow()
        self.db.commit()
        
        updated_alert = self.db.query(Alert).filter(Alert.id == alert.id).first()
        assert updated_alert.is_acknowledged == True
    
    def test_threat_intelligence(self):
        """Test threat intelligence integration"""
        from app.utils.threat_intel import ThreatIntelligenceClient
        
        # Mock threat intel for testing
        class MockThreatIntelligenceClient:
            def check_ip_reputation(self, ip):
                return {
                    "ip": ip,
                    "reputation_score": 75.0 if ip == "192.168.1.100" else 10.0,
                    "confidence": 0.8,
                    "details": {},
                    "last_updated": datetime.utcnow().isoformat()
                }
        
        client = MockThreatIntelligenceClient()
        
        # Test IP reputation
        result = client.check_ip_reputation("192.168.1.100")
        assert result["reputation_score"] == 75.0
        assert result["confidence"] == 0.8
        
        # Test bulk IP check
        results = client.check_bulk_ips(["192.168.1.100", "10.0.0.1"])
        assert len(results) == 2
        assert "192.168.1.100" in results
        assert "10.0.0.1" in results
    
    def test_timeline_reconstruction(self):
        """Test timeline reconstruction"""
        from app.analysis.timeline_reconstruction import TimelineReconstructor
        
        reconstructor = TimelineReconstructor()
        
        # Create timeline data
        start_time = datetime.utcnow() - timedelta(hours=1)
        end_time = datetime.utcnow()
        
        # Test reconstruction
        timeline = reconstructor.reconstruct_attack_timeline(
            self.db, start_time, end_time
        )
        
        assert "timeline_segments" in timeline
        assert "attack_sequences" in timeline
        assert "statistics" in timeline
        
        # Test report generation
        report = reconstructor.generate_timeline_report(timeline)
        
        assert "executive_summary" in report
        assert "detailed_findings" in report
        assert "recommendations" in report

# Run all tests
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
