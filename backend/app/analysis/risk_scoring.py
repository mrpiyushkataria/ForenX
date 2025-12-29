from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum
import math

class RiskLevel(Enum):
    """Risk level enumeration"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"

@dataclass
class RiskFactors:
    """Container for risk calculation factors"""
    # Volume factors
    request_count: int = 0
    error_count: int = 0
    data_volume: int = 0  # bytes
    
    # Diversity factors
    unique_endpoints: int = 0
    unique_ips: int = 0
    unique_user_agents: int = 0
    
    # Rate factors
    requests_per_second: float = 0.0
    errors_per_second: float = 0.0
    
    # Pattern factors
    sql_injection_attempts: int = 0
    xss_attempts: int = 0
    path_traversal_attempts: int = 0
    command_injection_attempts: int = 0
    
    # Context factors
    is_sensitive_endpoint: bool = False
    is_export_endpoint: bool = False
    is_authentication_endpoint: bool = False
    is_admin_endpoint: bool = False
    
    # Time factors
    activity_duration: float = 0.0  # seconds
    is_off_hours: bool = False
    
    # Threat intelligence
    ip_reputation_score: float = 0.0  # 0-100, higher is worse
    is_tor_exit_node: bool = False
    is_vpn_proxy: bool = False
    
    # Behavioral factors
    successful_logins: int = 0
    failed_logins: int = 0
    login_success_rate: float = 0.0

class AdvancedRiskScorer:
    """
    Advanced risk scoring engine with contextual awareness.
    Implements machine-learning-like scoring with multiple factor weights.
    """
    
    def __init__(self):
        # Configuration weights (sum to 1.0)
        self.weights = {
            "volume": 0.20,
            "diversity": 0.15,
            "rate": 0.15,
            "patterns": 0.25,
            "context": 0.10,
            "threat_intel": 0.10,
            "behavior": 0.05
        }
        
        # Thresholds for risk levels
        self.thresholds = {
            RiskLevel.CRITICAL: 90,
            RiskLevel.HIGH: 70,
            RiskLevel.MEDIUM: 40,
            RiskLevel.LOW: 20,
            RiskLevel.INFO: 0
        }
    
    def calculate_comprehensive_risk(self, factors: RiskFactors) -> Tuple[int, RiskLevel, Dict]:
        """
        Calculate comprehensive risk score with detailed breakdown.
        Returns: (score, level, breakdown)
        """
        breakdown = {}
        
        # Calculate component scores
        volume_score = self._calculate_volume_score(factors)
        diversity_score = self._calculate_diversity_score(factors)
        rate_score = self._calculate_rate_score(factors)
        pattern_score = self._calculate_pattern_score(factors)
        context_score = self._calculate_context_score(factors)
        threat_score = self._calculate_threat_intel_score(factors)
        behavior_score = self._calculate_behavior_score(factors)
        
        # Store component scores
        breakdown["components"] = {
            "volume": volume_score,
            "diversity": diversity_score,
            "rate": rate_score,
            "patterns": pattern_score,
            "context": context_score,
            "threat_intelligence": threat_score,
            "behavior": behavior_score
        }
        
        # Calculate weighted score
        weighted_score = (
            volume_score * self.weights["volume"] +
            diversity_score * self.weights["diversity"] +
            rate_score * self.weights["rate"] +
            pattern_score * self.weights["patterns"] +
            context_score * self.weights["context"] +
            threat_score * self.weights["threat_intel"] +
            behavior_score * self.weights["behavior"]
        )
        
        # Apply non-linear scaling (emphasize high scores)
        final_score = self._apply_nonlinear_scaling(weighted_score)
        
        # Determine risk level
        risk_level = self._determine_risk_level(final_score)
        
        # Calculate confidence
        confidence = self._calculate_confidence(
            factors, breakdown["components"]
        )
        
        breakdown["final_score"] = final_score
        breakdown["risk_level"] = risk_level.value
        breakdown["confidence"] = confidence
        breakdown["key_factors"] = self._identify_key_factors(
            factors, breakdown["components"]
        )
        
        return final_score, risk_level, breakdown
    
    def _calculate_volume_score(self, factors: RiskFactors) -> float:
        """Calculate score based on activity volume"""
        score = 0.0
        
        # Request volume
        if factors.request_count >= 10000:
            score += 90
        elif factors.request_count >= 5000:
            score += 70
        elif factors.request_count >= 1000:
            score += 50
        elif factors.request_count >= 500:
            score += 30
        elif factors.request_count >= 100:
            score += 15
        
        # Error volume
        if factors.error_count >= 1000:
            score += 80
        elif factors.error_count >= 500:
            score += 60
        elif factors.error_count >= 100:
            score += 40
        elif factors.error_count >= 50:
            score += 20
        elif factors.error_count >= 10:
            score += 10
        
        # Data volume (GB)
        gb = factors.data_volume / (1024 ** 3)
        if gb >= 10:
            score += 90
        elif gb >= 1:
            score += 70
        elif gb >= 0.1:  # 100MB
            score += 50
        elif gb >= 0.01:  # 10MB
            score += 30
        elif gb >= 0.001:  # 1MB
            score += 10
        
        return min(100.0, score)
    
    def _calculate_diversity_score(self, factors: RiskFactors) -> float:
        """Calculate score based on diversity of activity"""
        score = 0.0
        
        # Endpoint diversity
        if factors.unique_endpoints >= 200:
            score += 80
        elif factors.unique_endpoints >= 100:
            score += 60
        elif factors.unique_endpoints >= 50:
            score += 40
        elif factors.unique_endpoints >= 20:
            score += 20
        elif factors.unique_endpoints >= 10:
            score += 10
        
        # IP diversity (for distributed attacks)
        if factors.unique_ips >= 100:
            score += 70
        elif factors.unique_ips >= 50:
            score += 50
        elif factors.unique_ips >= 20:
            score += 30
        elif factors.unique_ips >= 10:
            score += 15
        elif factors.unique_ips >= 5:
            score += 5
        
        # User agent diversity
        if factors.unique_user_agents >= 20:
            score += 50
        elif factors.unique_user_agents >= 10:
            score += 30
        elif factors.unique_user_agents >= 5:
            score += 15
        elif factors.unique_user_agents >= 3:
            score += 5
        
        return min(100.0, score)
    
    def _calculate_rate_score(self, factors: RiskFactors) -> float:
        """Calculate score based on activity rate"""
        score = 0.0
        
        # Request rate
        if factors.requests_per_second >= 100:
            score += 90
        elif factors.requests_per_second >= 50:
            score += 70
        elif factors.requests_per_second >= 20:
            score += 50
        elif factors.requests_per_second >= 10:
            score += 30
        elif factors.requests_per_second >= 5:
            score += 15
        elif factors.requests_per_second >= 1:
            score += 5
        
        # Error rate
        if factors.errors_per_second >= 50:
            score += 80
        elif factors.errors_per_second >= 20:
            score += 60
        elif factors.errors_per_second >= 10:
            score += 40
        elif factors.errors_per_second >= 5:
            score += 20
        elif factors.errors_per_second >= 1:
            score += 10
        
        return min(100.0, score)
    
    def _calculate_pattern_score(self, factors: RiskFactors) -> float:
        """Calculate score based on attack patterns"""
        score = 0.0
        
        # SQL injection attempts
        if factors.sql_injection_attempts >= 50:
            score += 90
        elif factors.sql_injection_attempts >= 20:
            score += 70
        elif factors.sql_injection_attempts >= 10:
            score += 50
        elif factors.sql_injection_attempts >= 5:
            score += 30
        elif factors.sql_injection_attempts >= 1:
            score += 20
        
        # XSS attempts
        if factors.xss_attempts >= 50:
            score += 80
        elif factors.xss_attempts >= 20:
            score += 60
        elif factors.xss_attempts >= 10:
            score += 40
        elif factors.xss_attempts >= 5:
            score += 25
        elif factors.xss_attempts >= 1:
            score += 15
        
        # Path traversal attempts
        if factors.path_traversal_attempts >= 20:
            score += 70
        elif factors.path_traversal_attempts >= 10:
            score += 50
        elif factors.path_traversal_attempts >= 5:
            score += 30
        elif factors.path_traversal_attempts >= 1:
            score += 20
        
        # Command injection attempts
        if factors.command_injection_attempts >= 10:
            score += 80
        elif factors.command_injection_attempts >= 5:
            score += 60
        elif factors.command_injection_attempts >= 2:
            score += 40
        elif factors.command_injection_attempts >= 1:
            score += 30
        
        return min(100.0, score)
    
    def _calculate_context_score(self, factors: RiskFactors) -> float:
        """Calculate score based on context"""
        score = 0.0
        
        # Sensitive endpoint access
        if factors.is_sensitive_endpoint:
            score += 40
        
        # Export endpoint abuse
        if factors.is_export_endpoint:
            score += 30
        
        # Authentication endpoint targeting
        if factors.is_authentication_endpoint:
            score += 25
        
        # Admin endpoint targeting
        if factors.is_admin_endpoint:
            score += 35
        
        # Off-hours activity
        if factors.is_off_hours:
            score += 20
        
        # Short burst activity (automation indicator)
        if factors.activity_duration > 0:
            requests_per_second = factors.request_count / factors.activity_duration
            if requests_per_second > 10 and factors.activity_duration < 60:
                score += 30  # High rate in short time
        
        return min(100.0, score)
    
    def _calculate_threat_intel_score(self, factors: RiskFactors) -> float:
        """Calculate score based on threat intelligence"""
        score = 0.0
        
        # IP reputation
        if factors.ip_reputation_score >= 80:
            score += 90
        elif factors.ip_reputation_score >= 60:
            score += 70
        elif factors.ip_reputation_score >= 40:
            score += 50
        elif factors.ip_reputation_score >= 20:
            score += 30
        elif factors.ip_reputation_score > 0:
            score += 10
        
        # TOR exit node
        if factors.is_tor_exit_node:
            score += 40
        
        # VPN/Proxy
        if factors.is_vpn_proxy:
            score += 30
        
        return min(100.0, score)
    
    def _calculate_behavior_score(self, factors: RiskFactors) -> float:
        """Calculate score based on behavioral patterns"""
        score = 0.0
        
        # Failed login ratio
        total_logins = factors.successful_logins + factors.failed_logins
        if total_logins > 0:
            failure_ratio = factors.failed_logins / total_logins
            
            if failure_ratio >= 0.9:  # 90% failures
                score += 80
            elif failure_ratio >= 0.7:  # 70% failures
                score += 60
            elif failure_ratio >= 0.5:  # 50% failures
                score += 40
            elif failure_ratio >= 0.3:  # 30% failures
                score += 20
        
        # Login success rate (too high can indicate credential stuffing success)
        if factors.login_success_rate > 0:
            if factors.login_success_rate >= 0.3:  # 30% success rate
                score += 30
            elif factors.login_success_rate >= 0.1:  # 10% success rate
                score += 15
        
        return min(100.0, score)
    
    def _apply_nonlinear_scaling(self, score: float) -> int:
        """
        Apply non-linear scaling to emphasize high-risk scores.
        Uses exponential scaling for scores above 50.
        """
        if score <= 50:
            # Linear scaling for lower scores
            scaled = score * 2
        else:
            # Exponential scaling for higher scores
            base = (score - 50) / 50  # Normalize to 0-1
            scaled = 100 + (base ** 2) * 900  # Square for emphasis
        
        return int(min(1000, scaled))  # Cap at 1000 for extreme cases
    
    def _determine_risk_level(self, score: int) -> RiskLevel:
        """Determine risk level based on score"""
        if score >= self.thresholds[RiskLevel.CRITICAL]:
            return RiskLevel.CRITICAL
        elif score >= self.thresholds[RiskLevel.HIGH]:
            return RiskLevel.HIGH
        elif score >= self.thresholds[RiskLevel.MEDIUM]:
            return RiskLevel.MEDIUM
        elif score >= self.thresholds[RiskLevel.LOW]:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO
    
    def _calculate_confidence(
        self,
        factors: RiskFactors,
        component_scores: Dict[str, float]
    ) -> float:
        """
        Calculate confidence in the risk assessment.
        Higher when multiple indicators align.
        """
        # Count significant indicators (score > 50)
        significant_indicators = sum(
            1 for score in component_scores.values() if score > 50
        )
        
        # Base confidence on number of significant indicators
        if significant_indicators >= 4:
            confidence = 0.95
        elif significant_indicators >= 3:
            confidence = 0.85
        elif significant_indicators >= 2:
            confidence = 0.75
        elif significant_indicators >= 1:
            confidence = 0.65
        else:
            confidence = 0.50
        
        # Adjust based on data completeness
        data_completeness = self._calculate_data_completeness(factors)
        confidence *= data_completeness
        
        return round(confidence, 2)
    
    def _calculate_data_completeness(self, factors: RiskFactors) -> float:
        """Calculate how complete the risk factor data is"""
        completeness_score = 0.0
        total_possible = 0
        
        # Check each factor group
        if factors.request_count > 0:
            completeness_score += 1
        total_possible += 1
        
        if factors.data_volume > 0:
            completeness_score += 1
        total_possible += 1
        
        if factors.unique_endpoints > 0:
            completeness_score += 1
        total_possible += 1
        
        if factors.unique_ips > 0:
            completeness_score += 1
        total_possible += 1
        
        if factors.requests_per_second > 0:
            completeness_score += 1
        total_possible += 1
        
        # Pattern factors
        pattern_factors = [
            factors.sql_injection_attempts,
            factors.xss_attempts,
            factors.path_traversal_attempts,
            factors.command_injection_attempts
        ]
        if any(f > 0 for f in pattern_factors):
            completeness_score += 1
        total_possible += 1
        
        # Context factors
        context_factors = [
            factors.is_sensitive_endpoint,
            factors.is_export_endpoint,
            factors.is_authentication_endpoint,
            factors.is_admin_endpoint
        ]
        if any(context_factors):
            completeness_score += 1
        total_possible += 1
        
        return completeness_score / total_possible if total_possible > 0 else 0.5
    
    def _identify_key_factors(
        self,
        factors: RiskFactors,
        component_scores: Dict[str, float]
    ) -> List[Dict[str, any]]:
        """Identify and rank key factors contributing to risk score"""
        key_factors = []
        
        # Volume factors
        if factors.request_count >= 1000:
            key_factors.append({
                "factor": "high_request_volume",
                "value": f"{factors.request_count:,} requests",
                "impact": "high"
            })
        
        if factors.error_count >= 100:
            key_factors.append({
                "factor": "high_error_rate",
                "value": f"{factors.error_count:,} errors",
                "impact": "high"
            })
        
        # Pattern factors
        if factors.sql_injection_attempts >= 5:
            key_factors.append({
                "factor": "sql_injection_attempts",
                "value": f"{factors.sql_injection_attempts} attempts",
                "impact": "critical"
            })
        
        if factors.xss_attempts >= 5:
            key_factors.append({
                "factor": "xss_attempts",
                "value": f"{factors.xss_attempts} attempts",
                "impact": "high"
            })
        
        # Context factors
        if factors.is_sensitive_endpoint:
            key_factors.append({
                "factor": "sensitive_endpoint_access",
                "value": "Access to sensitive data endpoints",
                "impact": "high"
            })
        
        if factors.is_admin_endpoint:
            key_factors.append({
                "factor": "admin_endpoint_access",
                "value": "Access to administrative interfaces",
                "impact": "critical"
            })
        
        # Threat intelligence
        if factors.ip_reputation_score >= 60:
            key_factors.append({
                "factor": "poor_ip_reputation",
                "value": f"IP reputation score: {factors.ip_reputation_score}/100",
                "impact": "medium"
            })
        
        if factors.is_tor_exit_node:
            key_factors.append({
                "factor": "tor_exit_node",
                "value": "Traffic from TOR exit node",
                "impact": "medium"
            })
        
        # Sort by impact priority
        impact_priority = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        key_factors.sort(key=lambda x: impact_priority.get(x["impact"], 4))
        
        return key_factors
    
    def generate_risk_assessment_report(
        self,
        score: int,
        level: RiskLevel,
        breakdown: Dict,
        entity_type: str = "IP",
        entity_id: str = ""
    ) -> Dict:
        """Generate comprehensive risk assessment report"""
        report = {
            "metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "entity_type": entity_type,
                "entity_id": entity_id,
                "scorer_version": "2.0"
            },
            "executive_summary": {
                "risk_score": score,
                "risk_level": level.value,
                "confidence": breakdown.get("confidence", 0.0),
                "assessment": self._generate_risk_assessment(score, level)
            },
            "detailed_analysis": {
                "component_scores": breakdown.get("components", {}),
                "key_factors": breakdown.get("key_factors", []),
                "scoring_weights": self.weights
            },
            "recommendations": self._generate_risk_recommendations(score, level, breakdown)
        }
        
        return report
    
    def _generate_risk_assessment(self, score: int, level: RiskLevel) -> str:
        """Generate risk assessment description"""
        assessments = {
            RiskLevel.CRITICAL: (
                "CRITICAL risk requiring immediate attention. "
                "Multiple high-severity indicators detected with strong confidence. "
                "Likely indicates active attack or compromise."
            ),
            RiskLevel.HIGH: (
                "HIGH risk requiring prompt investigation. "
                "Several concerning indicators detected with good confidence. "
                "Potential security threat that needs verification."
            ),
            RiskLevel.MEDIUM: (
                "MEDIUM risk warranting monitoring. "
                "Some suspicious activity detected but may be benign. "
                "Recommend investigation when resources permit."
            ),
            RiskLevel.LOW: (
                "LOW risk with minimal concerns. "
                "Minor anomalies detected that are likely normal activity. "
                "No immediate action required."
            ),
            RiskLevel.INFO: (
                "INFORMATIONAL level with no significant risk. "
                "Activity appears normal or insufficient data for assessment."
            )
        }
        
        return assessments.get(level, "Risk assessment unavailable.")
    
    def _generate_risk_recommendations(
        self,
        score: int,
        level: RiskLevel,
        breakdown: Dict
    ) -> Dict[str, List[str]]:
        """Generate risk-based recommendations"""
        recommendations = {
            "immediate": [],
            "short_term": [],
            "long_term": []
        }
        
        key_factors = breakdown.get("key_factors", [])
        
        # Immediate actions for high/critical risk
        if level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
            recommendations["immediate"].extend([
                "Initiate incident response procedures",
                "Isolate affected systems if possible",
                "Preserve logs and evidence for investigation"
            ])
        
        # Factor-specific recommendations
        for factor in key_factors:
            factor_name = factor.get("factor", "")
            impact = factor.get("impact", "")
            
            if "sql_injection" in factor_name:
                recommendations["short_term"].extend([
                    "Implement Web Application Firewall (WAF)",
                    "Review and sanitize database queries",
                    "Update SQL injection detection rules"
                ])
            
            if "xss" in factor_name:
                recommendations["short_term"].extend([
                    "Implement Content Security Policy (CSP)",
                    "Sanitize all user inputs",
                    "Enable XSS protection headers"
                ])
            
            if "admin_endpoint" in factor_name:
                recommendations["immediate"].append(
                    "Review admin access logs and permissions"
                )
                recommendations["long_term"].append(
                    "Implement privileged access management"
                )
            
            if "tor_exit_node" in factor_name or "vpn_proxy" in factor_name:
                recommendations["short_term"].append(
                    "Consider blocking high-risk anonymizing services"
                )
        
        # General recommendations based on risk level
        if level == RiskLevel.CRITICAL:
            recommendations["immediate"].extend([
                "Engage security team immediately",
                "Consider system-wide security audit",
                "Implement emergency security controls"
            ])
        
        elif level == RiskLevel.HIGH:
            recommendations["short_term"].extend([
                "Schedule security review within 24 hours",
                "Increase monitoring for related entities",
                "Update threat intelligence feeds"
            ])
        
        # Remove duplicates
        for category in recommendations:
            recommendations[category] = list(set(recommendations[category]))
        
        return recommendations
