from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
from collections import defaultdict
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc

from app.models import LogEvent
import app.schemas as schemas

class TimelineReconstructor:
    """
    Advanced timeline reconstruction for forensic investigations.
    Reconstructs attack sequences and provides visual timelines.
    """
    
    def __init__(self, correlation_window_seconds: int = 10):
        self.correlation_window = timedelta(seconds=correlation_window_seconds)
    
    def reconstruct_attack_timeline(
        self,
        db: Session,
        start_time: datetime,
        end_time: datetime,
        target_ip: str = None,
        target_endpoint: str = None
    ) -> Dict:
        """
        Reconstruct complete attack timeline with correlated events.
        """
        # Get all events in time range
        query = db.query(LogEvent).filter(
            and_(
                LogEvent.timestamp >= start_time,
                LogEvent.timestamp <= end_time
            )
        )
        
        if target_ip:
            query = query.filter(LogEvent.ip == target_ip)
        
        if target_endpoint:
            query = query.filter(LogEvent.endpoint.like(f'%{target_endpoint}%'))
        
        events = query.order_by(LogEvent.timestamp).all()
        
        # Group events by correlation windows
        timeline = self._create_timeline_segments(events)
        
        # Find attack sequences
        attack_sequences = self._find_attack_sequences(timeline)
        
        # Calculate statistics
        stats = self._calculate_timeline_statistics(events, attack_sequences)
        
        return {
            "time_range": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat(),
                "duration_seconds": (end_time - start_time).total_seconds()
            },
            "total_events": len(events),
            "unique_ips": len(set(e.ip for e in events if e.ip)),
            "unique_endpoints": len(set(e.endpoint for e in events if e.endpoint)),
            "timeline_segments": timeline,
            "attack_sequences": attack_sequences,
            "statistics": stats,
            "visualization_data": self._prepare_visualization_data(timeline, attack_sequences)
        }
    
    def _create_timeline_segments(self, events: List[LogEvent]) -> List[Dict]:
        """Create timeline segments grouped by time windows"""
        if not events:
            return []
        
        events.sort(key=lambda x: x.timestamp)
        
        segments = []
        current_segment = {
            "start_time": events[0].timestamp,
            "end_time": events[0].timestamp,
            "events": [],
            "event_count": 0,
            "sources": set(),
            "ips": set()
        }
        
        for event in events:
            # Check if event fits in current segment
            if event.timestamp - current_segment["end_time"] <= self.correlation_window:
                current_segment["end_time"] = event.timestamp
                current_segment["events"].append(self._event_to_dict(event))
                current_segment["event_count"] += 1
                current_segment["sources"].add(event.source)
                if event.ip:
                    current_segment["ips"].add(event.ip)
            else:
                # Finalize current segment
                if current_segment["events"]:
                    segments.append(self._finalize_segment(current_segment))
                
                # Start new segment
                current_segment = {
                    "start_time": event.timestamp,
                    "end_time": event.timestamp,
                    "events": [self._event_to_dict(event)],
                    "event_count": 1,
                    "sources": {event.source},
                    "ips": {event.ip} if event.ip else set()
                }
        
        # Add last segment
        if current_segment["events"]:
            segments.append(self._finalize_segment(current_segment))
        
        return segments
    
    def _finalize_segment(self, segment: Dict) -> Dict:
        """Finalize segment with calculated fields"""
        segment["sources"] = list(segment["sources"])
        segment["ips"] = list(segment["ips"])
        segment["duration_seconds"] = (segment["end_time"] - segment["start_time"]).total_seconds()
        
        # Calculate segment risk score
        segment["risk_score"] = self._calculate_segment_risk(segment)
        
        # Determine segment type
        segment["type"] = self._determine_segment_type(segment)
        
        return segment
    
    def _event_to_dict(self, event: LogEvent) -> Dict:
        """Convert LogEvent to dictionary for serialization"""
        return {
            "id": event.id,
            "timestamp": event.timestamp.isoformat(),
            "source": event.source,
            "ip": event.ip,
            "method": event.method,
            "endpoint": event.endpoint,
            "status": event.status,
            "response_size": event.response_size,
            "risk_score": event.risk_score,
            "has_payload": bool(event.payload),
            "payload_preview": event.payload[:100] if event.payload else None
        }
    
    def _calculate_segment_risk(self, segment: Dict) -> int:
        """Calculate risk score for timeline segment"""
        score = 0
        
        # Event count factor
        if segment["event_count"] >= 100:
            score += 40
        elif segment["event_count"] >= 50:
            score += 30
        elif segment["event_count"] >= 20:
            score += 20
        elif segment["event_count"] >= 10:
            score += 10
        
        # Source diversity factor
        if len(segment["sources"]) >= 3:
            score += 20
        elif len(segment["sources"]) >= 2:
            score += 10
        
        # IP diversity factor
        if len(segment["ips"]) >= 5:
            score += 25
        elif len(segment["ips"]) >= 3:
            score += 15
        elif len(segment["ips"]) >= 2:
            score += 5
        
        # Individual event risk scores
        event_risk_sum = sum(e.get("risk_score", 0) for e in segment["events"])
        avg_event_risk = event_risk_sum / max(1, segment["event_count"])
        score += int(avg_event_risk * 0.5)  # 50% weight
        
        # Duration factor (short bursts are suspicious)
        if segment["duration_seconds"] > 0:
            events_per_second = segment["event_count"] / segment["duration_seconds"]
            if events_per_second >= 10:
                score += 30
            elif events_per_second >= 5:
                score += 20
            elif events_per_second >= 1:
                score += 10
        
        return min(100, score)
    
    def _determine_segment_type(self, segment: Dict) -> str:
        """Determine the type of activity in segment"""
        events = segment["events"]
        
        # Check for attack patterns
        error_count = sum(1 for e in events if e.get("status") and 400 <= e["status"] < 600)
        success_count = sum(1 for e in events if e.get("status") == 200)
        
        if error_count > success_count * 2:  # Mostly errors
            return "error_activity"
        
        # Check for data transfer
        total_data = sum(e.get("response_size", 0) for e in events)
        if total_data > 10 * 1024 * 1024:  # > 10MB
            return "data_transfer"
        
        # Check for scanning
        unique_endpoints = len(set(e.get("endpoint") for e in events if e.get("endpoint")))
        if unique_endpoints > segment["event_count"] * 0.8:  # High endpoint diversity
            return "scanning"
        
        # Check for authentication activity
        auth_endpoints = ['/login', '/auth', '/signin', '/wp-login']
        auth_events = sum(1 for e in events if any(
            auth in (e.get("endpoint") or "").lower() for auth in auth_endpoints
        ))
        if auth_events > 0:
            return "authentication"
        
        return "normal_activity"
    
    def _find_attack_sequences(self, timeline: List[Dict]) -> List[Dict]:
        """Find potential attack sequences in timeline"""
        sequences = []
        current_sequence = None
        
        for i, segment in enumerate(timeline):
            if segment["risk_score"] >= 50:  # High risk segment
                if current_sequence is None:
                    # Start new sequence
                    current_sequence = {
                        "start_index": i,
                        "segments": [segment],
                        "total_risk": segment["risk_score"],
                        "start_time": segment["start_time"],
                        "end_time": segment["end_time"]
                    }
                else:
                    # Check if segment is contiguous (within 5 minutes)
                    time_gap = segment["start_time"] - current_sequence["end_time"]
                    if time_gap.total_seconds() <= 300:  # 5 minutes
                        # Add to current sequence
                        current_sequence["segments"].append(segment)
                        current_sequence["total_risk"] += segment["risk_score"]
                        current_sequence["end_time"] = segment["end_time"]
                    else:
                        # Finalize current sequence and start new
                        sequences.append(self._finalize_sequence(current_sequence))
                        current_sequence = {
                            "start_index": i,
                            "segments": [segment],
                            "total_risk": segment["risk_score"],
                            "start_time": segment["start_time"],
                            "end_time": segment["end_time"]
                        }
            else:
                # Low risk segment, finalize current sequence if exists
                if current_sequence is not None:
                    sequences.append(self._finalize_sequence(current_sequence))
                    current_sequence = None
        
        # Finalize any remaining sequence
        if current_sequence is not None:
            sequences.append(self._finalize_sequence(current_sequence))
        
        return sequences
    
    def _finalize_sequence(self, sequence: Dict) -> Dict:
        """Finalize attack sequence with analysis"""
        sequence["segment_count"] = len(sequence["segments"])
        sequence["duration_seconds"] = (sequence["end_time"] - sequence["start_time"]).total_seconds()
        sequence["avg_risk_score"] = sequence["total_risk"] / sequence["segment_count"]
        
        # Collect all events from sequence
        all_events = []
        for segment in sequence["segments"]:
            all_events.extend(segment["events"])
        
        # Analyze sequence
        sequence["analysis"] = self._analyze_sequence(all_events)
        sequence["confidence"] = self._calculate_sequence_confidence(sequence)
        
        return sequence
    
    def _analyze_sequence(self, events: List[Dict]) -> Dict:
        """Analyze events in sequence for attack patterns"""
        analysis = {
            "event_types": defaultdict(int),
            "sources": set(),
            "ips": set(),
            "endpoints": set(),
            "status_codes": defaultdict(int),
            "total_data": 0
        }
        
        for event in events:
            analysis["event_types"][event.get("source", "unknown")] += 1
            analysis["sources"].add(event.get("source"))
            if event.get("ip"):
                analysis["ips"].add(event["ip"])
            if event.get("endpoint"):
                analysis["endpoints"].add(event["endpoint"])
            if event.get("status"):
                analysis["status_codes"][event["status"]] += 1
            analysis["total_data"] += event.get("response_size", 0)
        
        # Convert sets to lists for serialization
        analysis["sources"] = list(analysis["sources"])
        analysis["ips"] = list(analysis["ips"])
        analysis["endpoints"] = list(analysis["endpoints"])[:20]  # Limit
        
        # Determine likely attack type
        analysis["likely_attack_type"] = self._determine_attack_type(analysis)
        
        return analysis
    
    def _determine_attack_type(self, analysis: Dict) -> str:
        """Determine likely attack type from analysis"""
        event_types = analysis["event_types"]
        status_codes = analysis["status_codes"]
        endpoints = analysis["endpoints"]
        
        # Check for brute force
        auth_endpoints = sum(1 for ep in endpoints if any(
            auth in ep.lower() for auth in ['login', 'auth', 'signin', 'wp-login']
        ))
        error_401_403 = status_codes.get(401, 0) + status_codes.get(403, 0)
        
        if auth_endpoints > 0 and error_401_403 > 10:
            return "brute_force_attack"
        
        # Check for SQL injection
        sql_endpoints = sum(1 for ep in endpoints if any(
            sql in ep.lower() for sql in ['sql', 'select', 'union', 'database']
        ))
        if sql_endpoints > 0:
            return "sql_injection_attempt"
        
        # Check for scanning
        if len(endpoints) > 50:
            return "reconnaissance_scanning"
        
        # Check for data exfiltration
        if analysis["total_data"] > 100 * 1024 * 1024:  # > 100MB
            return "data_exfiltration"
        
        # Check for DDoS
        if sum(event_types.values()) > 1000:
            return "ddos_attack"
        
        return "suspicious_activity"
    
    def _calculate_sequence_confidence(self, sequence: Dict) -> float:
        """Calculate confidence score for attack sequence"""
        confidence = 0.0
        
        # Segment count confidence
        if sequence["segment_count"] >= 5:
            confidence += 0.4
        elif sequence["segment_count"] >= 3:
            confidence += 0.3
        elif sequence["segment_count"] >= 2:
            confidence += 0.2
        else:
            confidence += 0.1
        
        # Risk score confidence
        if sequence["avg_risk_score"] >= 80:
            confidence += 0.4
        elif sequence["avg_risk_score"] >= 60:
            confidence += 0.3
        elif sequence["avg_risk_score"] >= 40:
            confidence += 0.2
        else:
            confidence += 0.1
        
        # Duration confidence (longer is more confident)
        if sequence["duration_seconds"] >= 3600:  # 1 hour
            confidence += 0.2
        elif sequence["duration_seconds"] >= 600:  # 10 minutes
            confidence += 0.1
        
        return min(1.0, confidence)
    
    def _calculate_timeline_statistics(self, events: List[LogEvent], sequences: List[Dict]) -> Dict:
        """Calculate timeline statistics"""
        if not events:
            return {}
        
        # Basic statistics
        stats = {
            "total_events": len(events),
            "time_range_seconds": (events[-1].timestamp - events[0].timestamp).total_seconds(),
            "events_per_second": len(events) / max(1, (events[-1].timestamp - events[0].timestamp).total_seconds()),
            "sources": defaultdict(int),
            "status_codes": defaultdict(int),
            "methods": defaultdict(int)
        }
        
        for event in events:
            stats["sources"][event.source] += 1
            if event.status:
                stats["status_codes"][event.status] += 1
            if event.method:
                stats["methods"][event.method] += 1
        
        # Attack sequence statistics
        stats["attack_sequences"] = len(sequences)
        stats["high_risk_segments"] = sum(1 for seq in sequences if seq["avg_risk_score"] >= 70)
        stats["total_attack_duration"] = sum(seq["duration_seconds"] for seq in sequences)
        
        # Risk distribution
        risk_scores = [e.risk_score for e in events if e.risk_score]
        if risk_scores:
            stats["avg_risk_score"] = sum(risk_scores) / len(risk_scores)
            stats["max_risk_score"] = max(risk_scores)
            stats["high_risk_events"] = sum(1 for score in risk_scores if score >= 70)
        else:
            stats["avg_risk_score"] = 0
            stats["max_risk_score"] = 0
            stats["high_risk_events"] = 0
        
        return stats
    
    def _prepare_visualization_data(self, timeline: List[Dict], sequences: List[Dict]) -> Dict:
        """Prepare data for timeline visualization"""
        viz_data = {
            "timeline_points": [],
            "sequences": [],
            "heatmap_data": defaultdict(int)
        }
        
        # Create timeline points for visualization
        for segment in timeline:
            viz_data["timeline_points"].append({
                "time": segment["start_time"].isoformat(),
                "value": segment["event_count"],
                "risk": segment["risk_score"],
                "type": segment["type"]
            })
        
        # Create sequence data
        for seq in sequences:
            viz_data["sequences"].append({
                "start": seq["start_time"].isoformat(),
                "end": seq["end_time"].isoformat(),
                "risk": seq["avg_risk_score"],
                "type": seq["analysis"]["likely_attack_type"]
            })
        
        # Create heatmap data (events per minute)
        for segment in timeline:
            minute_key = segment["start_time"].strftime("%Y-%m-%d %H:%M")
            viz_data["heatmap_data"][minute_key] += segment["event_count"]
        
        # Convert heatmap data to list
        viz_data["heatmap"] = [
            {"time": k, "count": v}
            for k, v in sorted(viz_data["heatmap_data"].items())
        ]
        
        return viz_data
    
    def generate_timeline_report(self, timeline_data: Dict) -> Dict:
        """Generate comprehensive timeline report"""
        report = {
            "executive_summary": self._generate_executive_summary(timeline_data),
            "detailed_findings": [],
            "recommendations": [],
            "timeline_visualization": timeline_data.get("visualization_data", {}),
            "metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "time_range": timeline_data.get("time_range", {}),
                "total_events": timeline_data.get("total_events", 0)
            }
        }
        
        # Add findings for each attack sequence
        for i, sequence in enumerate(timeline_data.get("attack_sequences", [])):
            finding = {
                "sequence_id": i + 1,
                "time_range": f"{sequence['start_time']} to {sequence['end_time']}",
                "duration": f"{sequence['duration_seconds']:.1f} seconds",
                "segment_count": sequence["segment_count"],
                "avg_risk_score": sequence["avg_risk_score"],
                "confidence": f"{sequence['confidence']:.1%}",
                "likely_attack_type": sequence["analysis"]["likely_attack_type"],
                "involved_ips": sequence["analysis"]["ips"][:10],  # Limit
                "event_sources": sequence["analysis"]["sources"],
                "key_indicators": self._extract_key_indicators(sequence)
            }
            report["detailed_findings"].append(finding)
        
        # Generate recommendations
        report["recommendations"] = self._generate_timeline_recommendations(timeline_data)
        
        return report
    
    def _generate_executive_summary(self, timeline_data: Dict) -> str:
        """Generate executive summary of timeline analysis"""
        stats = timeline_data.get("statistics", {})
        sequences = timeline_data.get("attack_sequences", [])
        
        summary_parts = [
            f"Timeline analysis covered {stats.get('total_events', 0):,} events "
            f"over {stats.get('time_range_seconds', 0):.0f} seconds."
        ]
        
        if sequences:
            summary_parts.append(
                f"Detected {len(sequences)} potential attack sequences "
                f"with {stats.get('high_risk_segments', 0)} high-risk segments."
            )
            
            # List top attack types
            attack_types = defaultdict(int)
            for seq in sequences:
                attack_types[seq["analysis"]["likely_attack_type"]] += 1
            
            if attack_types:
                top_attacks = sorted(attack_types.items(), key=lambda x: x[1], reverse=True)[:3]
                summary_parts.append(
                    "Primary attack types: " + ", ".join(
                        f"{atype} ({count})" for atype, count in top_attacks
                    )
                )
        else:
            summary_parts.append("No significant attack sequences detected.")
        
        # Add risk assessment
        avg_risk = stats.get("avg_risk_score", 0)
        if avg_risk >= 70:
            risk_level = "HIGH"
        elif avg_risk >= 40:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        summary_parts.append(f"Overall risk assessment: {risk_level} (avg score: {avg_risk:.1f})")
        
        return " ".join(summary_parts)
    
    def _extract_key_indicators(self, sequence: Dict) -> List[str]:
        """Extract key indicators from attack sequence"""
        indicators = []
        analysis = sequence["analysis"]
        
        # Event volume indicator
        total_events = sum(analysis["event_types"].values())
        if total_events > 100:
            indicators.append(f"High event volume ({total_events} events)")
        
        # Error rate indicator
        error_codes = [401, 403, 404, 500, 502, 503]
        error_count = sum(analysis["status_codes"].get(code, 0) for code in error_codes)
        if error_count > total_events * 0.3:  # >30% errors
            indicators.append(f"High error rate ({error_count/total_events:.0%})")
        
        # Source diversity indicator
        if len(analysis["sources"]) >= 3:
            indicators.append(f"Multiple log sources ({len(analysis['sources'])})")
        
        # IP diversity indicator
        if len(analysis["ips"]) >= 5:
            indicators.append(f"Multiple IPs involved ({len(analysis['ips'])})")
        
        # Data transfer indicator
        if analysis["total_data"] > 10 * 1024 * 1024:  # >10MB
            mb = analysis["total_data"] / (1024 * 1024)
            indicators.append(f"Large data transfer ({mb:.1f} MB)")
        
        return indicators
    
    def _generate_timeline_recommendations(self, timeline_data: Dict) -> List[str]:
        """Generate recommendations based on timeline analysis"""
        recommendations = []
        stats = timeline_data.get("statistics", {})
        sequences = timeline_data.get("attack_sequences", [])
        
        # General recommendations
        recommendations.append(
            "Implement centralized logging with real-time monitoring"
        )
        
        if stats.get("total_events", 0) > 10000:
            recommendations.append(
                "Consider implementing a Security Information and Event Management (SIEM) system"
            )
        
        # Recommendations based on attack sequences
        for sequence in sequences:
            attack_type = sequence["analysis"]["likely_attack_type"]
            
            if attack_type == "brute_force_attack":
                recommendations.extend([
                    "Implement account lockout after 5 failed attempts",
                    "Enable multi-factor authentication",
                    "Rate limit authentication endpoints"
                ])
            
            elif attack_type == "sql_injection_attempt":
                recommendations.extend([
                    "Implement parameterized queries or ORM",
                    "Deploy Web Application Firewall (WAF)",
                    "Regular SQL injection testing"
                ])
            
            elif attack_type == "reconnaissance_scanning":
                recommendations.extend([
                    "Implement fail2ban for repeated 404 errors",
                    "Hide server banners and version information",
                    "Monitor for directory brute force attempts"
                ])
            
            elif attack_type == "data_exfiltration":
                recommendations.extend([
                    "Implement Data Loss Prevention (DLP)",
                    "Monitor large data transfers",
                    "Review access controls for sensitive data"
                ])
            
            elif attack_type == "ddos_attack":
                recommendations.extend([
                    "Implement DDoS protection service",
                    "Configure rate limiting per IP",
                    "Use CDN for static content"
                ])
        
        # Remove duplicates
        return list(set(recommendations))
