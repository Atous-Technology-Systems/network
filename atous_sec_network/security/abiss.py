"""
ABISS - Adaptive Behaviour Intelligence Security System
Sistema adaptativo de detecção e resposta a ameaças em tempo real
"""
import logging
import numpy as np
import threading
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import statistics
import time
import json


def send_alert(message: str, channels: List[str], severity: str = "info") -> bool:
    """Send alert through specified channels (mock implementation)"""
    logger = logging.getLogger(__name__)
    logger.info(f"ALERT [{severity.upper()}] via {channels}: {message}")
    return True

class ABISS:
    """
    Adaptive Behaviour Intelligence Security System (ABISS)
    - Behavioral profiling
    - Anomaly detection (statistical, ML, rule-based)
    - Adaptive response
    - Integration with P2P, OTA, and NNIS
    """
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.behavior_profiles = {}
        self.anomaly_history = []
        self.response_history = []
        self.behavioral_baselines = {}
        self.quarantined_nodes = {}
        self.threat_intelligence = []
        self._lock = threading.RLock()  # Thread safety
        # Placeholder for Gemma 3N model integration
        self.gemma_model = None
        self._initialize_models()

    def _initialize_models(self):
        """Initialize Gemma 3N or other ML models"""
        self.logger.info("Initializing Gemma 3N model (placeholder)")
        # TODO: Load Gemma 3N or other models
        self.gemma_model = None

    def profile_behavior(self, node_id: str, data: Dict[str, Any]) -> None:
        """Update behavioral profile for a node"""
        self.logger.debug(f"Profiling behavior for node {node_id}")
        # TODO: Implement behavioral profiling logic
        self.behavior_profiles[node_id] = data

    def detect_anomaly(self, node_id: str, data: Dict[str, Any]) -> bool:
        """Detect anomalies in node behavior"""
        self.logger.debug(f"Detecting anomaly for node {node_id}")
        # TODO: Implement anomaly detection logic (statistical, ML, rule-based)
        return False

    def adaptive_response(self, node_id: str, anomaly: bool) -> None:
        """Trigger adaptive response to detected anomaly"""
        self.logger.info(f"Adaptive response for node {node_id}, anomaly={anomaly}")
        # TODO: Implement adaptive response (quarantine, reconfig, alert)
        self.response_history.append({"node": node_id, "anomaly": anomaly})

    def integrate_with_p2p(self, p2p_manager: Any) -> None:
        """Integrate with P2P manager for network-wide actions"""
        self.logger.info("Integrating ABISS with P2P manager (placeholder)")
        # TODO: Implement integration logic

    def integrate_with_ota(self, ota_manager: Any) -> None:
        """Integrate with OTA update system"""
        self.logger.info("Integrating ABISS with OTA manager (placeholder)")
        # TODO: Implement integration logic

    def integrate_with_nnis(self, nnis_engine: Any) -> None:
        """Integrate with NNIS for layered defense"""
        self.logger.info("Integrating ABISS with NNIS (placeholder)")
        # TODO: Implement integration logic

    def get_status(self) -> Dict[str, Any]:
        """Return current status and metrics"""
        return {
            "profiles": list(self.behavior_profiles.keys()),
            "anomalies": len(self.anomaly_history),
            "responses": len(self.response_history),
            "quarantined_nodes": len(self.quarantined_nodes),
            "baselines": len(self.behavioral_baselines)
        }
    
    # Advanced Behavioral Profiling Methods
    def create_behavioral_baseline(self, node_id: str, historical_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create behavioral baseline from historical data"""
        with self._lock:
            if not historical_data:
                raise ValueError("Historical data cannot be empty")
            
            baseline = {}
            
            # Extract metrics from historical data
            metrics = {}
            for data_point in historical_data:
                for key, value in data_point.items():
                    if key != "timestamp" and isinstance(value, (int, float)):
                        if key not in metrics:
                            metrics[key] = []
                        metrics[key].append(value)
            
            # Calculate statistical baseline for each metric
            for metric, values in metrics.items():
                if values:
                    baseline[metric] = {
                        "mean": statistics.mean(values),
                        "std": statistics.stdev(values) if len(values) > 1 else 0,
                        "median": statistics.median(values),
                        "percentiles": {
                            "p25": np.percentile(values, 25),
                            "p75": np.percentile(values, 75),
                            "p90": np.percentile(values, 90),
                            "p95": np.percentile(values, 95)
                        },
                        "min": min(values),
                        "max": max(values)
                    }
            
            # Add metadata
            baseline["history"] = historical_data.copy()
            baseline["created_at"] = datetime.now().isoformat()
            baseline["current_stats"] = baseline.copy()
            
            self.behavioral_baselines[node_id] = baseline
            self.logger.info(f"Created behavioral baseline for node {node_id}")
            return baseline
    
    def update_behavioral_profile_sliding_window(self, node_id: str, new_data: Dict[str, Any], window_size: int = 100) -> Dict[str, Any]:
        """Update behavioral profile using sliding window"""
        with self._lock:
            if node_id not in self.behavior_profiles:
                self.behavior_profiles[node_id] = {"history": [], "current_stats": {}}
            
            profile = self.behavior_profiles[node_id]
            
            # Ensure history field exists
            if "history" not in profile:
                profile["history"] = []
            
            # Add timestamp to new data
            timestamped_data = {**new_data, "timestamp": datetime.now()}
            profile["history"].append(timestamped_data)
            
            # Maintain sliding window
            if len(profile["history"]) > window_size:
                profile["history"] = profile["history"][-window_size:]
            
            # Update current statistics
            self._update_current_stats(node_id)
            
            self.logger.debug(f"Updated behavioral profile for node {node_id} (window size: {len(profile['history'])})")
            
            return profile
    
    def _update_current_stats(self, node_id: str) -> None:
        """Update current statistics for a node"""
        profile = self.behavior_profiles[node_id]
        history = profile["history"]
        
        if not history:
            return
        
        # Extract metrics
        metrics = {}
        for data_point in history:
            for key, value in data_point.items():
                if key != "timestamp" and isinstance(value, (int, float)):
                    if key not in metrics:
                        metrics[key] = []
                    metrics[key].append(value)
        
        # Calculate current statistics
        current_stats = {}
        for metric, values in metrics.items():
            if values:
                current_stats[metric] = {
                    "mean": statistics.mean(values),
                    "std": statistics.stdev(values) if len(values) > 1 else 0,
                    "recent_trend": self._calculate_trend(values[-10:]) if len(values) >= 10 else 0
                }
        
        profile["current_stats"] = current_stats
    
    def _calculate_trend(self, values: List[float]) -> float:
        """Calculate trend using simple linear regression"""
        if len(values) < 2:
            return 0
        
        x = list(range(len(values)))
        n = len(values)
        
        # Simple linear regression slope
        sum_x = sum(x)
        sum_y = sum(values)
        sum_xy = sum(x[i] * values[i] for i in range(n))
        sum_x2 = sum(xi * xi for xi in x)
        
        slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x)
        return slope
    
    def get_behavioral_profile(self, node_id: str) -> Optional[Dict[str, Any]]:
        """Get behavioral profile for a node"""
        with self._lock:
            return self.behavior_profiles.get(node_id)
    
    def calculate_behavioral_score(self, node_id: str, current_data: Dict[str, Any]) -> float:
        """Calculate normalized behavioral score (0-1) - higher values indicate more deviation"""
        with self._lock:
            if node_id not in self.behavioral_baselines:
                self.logger.warning(f"No baseline found for node {node_id}")
                return 0.5  # Neutral score
            
            baseline = self.behavioral_baselines[node_id]
            total_deviation = 0
            metric_count = 0
            
            for metric, value in current_data.items():
                if isinstance(value, (int, float)) and metric in baseline:
                    baseline_stats = baseline[metric]
                    mean = baseline_stats["mean"]
                    std = baseline_stats["std"]
                    
                    if std > 0:
                        # Calculate Z-score and normalize
                        z_score = abs(value - mean) / std
                        # Convert Z-score to 0-1 scale with higher sensitivity
                        deviation = min(z_score / 2.0, 1.0)  # More sensitive than 3 sigma
                        total_deviation += deviation
                        metric_count += 1
                    else:
                        # If std is 0, any deviation is significant
                        if value != mean:
                            total_deviation += 1.0
                        metric_count += 1
            
            if metric_count == 0:
                return 0.5
            
            # Average deviation score
            score = total_deviation / metric_count
            return min(score, 1.0)
    
    # Advanced Anomaly Detection Methods
    def detect_statistical_anomaly_zscore(self, values: List[float], threshold: float = 2.0) -> bool:
        """Detect anomalies using Z-score statistical method"""
        if len(values) < 2:
            return False
        
        mean = statistics.mean(values[:-1])  # Exclude last value from baseline
        std = statistics.stdev(values[:-1]) if len(values) > 2 else 0
        
        if std == 0:
            return False
        
        current_value = values[-1]
        z_score = abs(current_value - mean) / std
        
        return z_score > threshold
    
    def detect_ml_anomaly_isolation_forest(self, training_data: np.ndarray, test_data: np.ndarray, contamination: float = 0.1) -> List[int]:
        """Detect anomalies using Isolation Forest ML algorithm"""
        try:
            # Initialize and train Isolation Forest
            iso_forest = IsolationForest(contamination=contamination, random_state=42)
            iso_forest.fit(training_data)
            
            # Predict anomalies (-1 for anomaly, 1 for normal)
            predictions = iso_forest.predict(test_data)
            
            return predictions.tolist()
        except Exception as e:
            self.logger.error(f"Error in Isolation Forest anomaly detection: {e}")
            return [1] * len(test_data)  # Return all normal if error
    
    def detect_rule_based_anomaly(self, data: Dict[str, Any], rules: Dict[str, Dict[str, float]]) -> List[str]:
        """Detect anomalies using rule-based heuristics"""
        violations = []
        
        for metric, value in data.items():
            if metric in rules and isinstance(value, (int, float)):
                rule = rules[metric]
                
                # Check maximum threshold
                if "max" in rule and value > rule["max"]:
                    violations.append(metric)
                    self.logger.warning(f"Rule violation: {metric} = {value} > {rule['max']}")
                
                # Check minimum threshold
                if "min" in rule and value < rule["min"]:
                    violations.append(metric)
                    self.logger.warning(f"Rule violation: {metric} = {value} < {rule['min']}")
        
        return violations
    
    def detect_composite_anomaly(self, node_id: str, current_data: Dict[str, Any], 
                                methods: List[str] = None, consensus_threshold: float = 0.6) -> Dict[str, Any]:
        """Detect anomalies using multiple methods and consensus"""
        if methods is None:
            methods = ["statistical", "ml", "rule_based"]
        
        results = {}
        methods_triggered = []
        
        # Statistical method
        if "statistical" in methods and node_id in self.behavioral_baselines:
            score = self.calculate_behavioral_score(node_id, current_data)
            if score > 0.7:  # High deviation threshold
                methods_triggered.append("statistical")
                results["statistical"] = {"score": score, "triggered": True}
            else:
                results["statistical"] = {"score": score, "triggered": False}
        
        # ML method (simplified for demo)
        if "ml" in methods:
            # Create simple feature vector
            features = []
            for key, value in current_data.items():
                if isinstance(value, (int, float)):
                    features.append(value)
            
            if features:
                # Simple threshold-based ML simulation
                feature_mean = statistics.mean(features)
                if feature_mean > 80:  # Arbitrary threshold for demo
                    methods_triggered.append("ml")
                    results["ml"] = {"score": feature_mean / 100, "triggered": True}
                else:
                    results["ml"] = {"score": feature_mean / 100, "triggered": False}
        
        # Rule-based method
        if "rule_based" in methods:
            default_rules = {
                "cpu_usage": {"max": 90},
                "memory_usage": {"max": 95},
                "failed_logins": {"max": 10},
                "network_connections": {"max": 500}
            }
            violations = self.detect_rule_based_anomaly(current_data, default_rules)
            if violations:
                methods_triggered.append("rule_based")
                results["rule_based"] = {"violations": violations, "triggered": True}
            else:
                results["rule_based"] = {"violations": [], "triggered": False}
        
        # Calculate consensus
        triggered_count = len(methods_triggered)
        total_methods = len(methods)
        confidence = triggered_count / total_methods if total_methods > 0 else 0
        
        is_anomaly = confidence >= consensus_threshold
        
        return {
            "is_anomaly": is_anomaly,
            "confidence": confidence,
            "methods_triggered": methods_triggered,
            "method_results": results,
            "consensus_threshold": consensus_threshold
        }
    
    # Advanced Adaptive Response Methods
    def quarantine_node(self, node_id: str, threat_level: str, reason: str, duration_minutes: int = 30) -> Dict[str, Any]:
        """Quarantine a malicious node"""
        with self._lock:
            quarantine_until = datetime.now() + timedelta(minutes=duration_minutes)
            
            quarantine_info = {
                "status": "quarantined",
                "node_id": node_id,
                "threat_level": threat_level,
                "reason": reason,
                "quarantine_start": datetime.now().isoformat(),
                "quarantine_until": quarantine_until.isoformat(),
                "duration_minutes": duration_minutes
            }
            
            self.quarantined_nodes[node_id] = quarantine_info
            
            self.logger.critical(f"Node {node_id} quarantined: {reason} (threat level: {threat_level})")
            
            # Add to response history
            self.response_history.append({
                "action": "quarantine",
                "node_id": node_id,
                "timestamp": datetime.now().isoformat(),
                "details": quarantine_info
            })
            
            return quarantine_info
    
    def dynamic_reconfiguration(self, node_id: str, threat_assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Dynamically reconfigure parameters based on threat assessment"""
        threat_type = threat_assessment.get("type", "unknown")
        severity = threat_assessment.get("severity", "low")
        target = threat_assessment.get("target", "general")
        
        config_changes = {}
        
        # Authentication-related reconfigurations
        if target == "authentication" or threat_type == "brute_force":
            config_changes["authentication"] = {
                "max_attempts": 2 if severity == "high" else 3,
                "lockout_duration": 1800 if severity == "high" else 900,
                "require_2fa": True if severity in ["high", "critical"] else False
            }
        
        # Network-related reconfigurations
        if threat_type in ["ddos", "port_scan", "network_intrusion"]:
            config_changes["network"] = {
                "rate_limit": 10 if severity == "high" else 50,
                "connection_timeout": 5 if severity == "high" else 30,
                "enable_geo_blocking": True if severity in ["high", "critical"] else False
            }
        
        # Monitoring reconfigurations
        monitoring_frequency = {
            "low": "normal",
            "medium": "increased",
            "high": "high",
            "critical": "maximum"
        }.get(severity, "normal")
        
        config_changes["monitoring"] = {
            "frequency": "high" if severity in ["medium", "high", "critical"] else "normal",
            "log_level": "DEBUG" if severity in ["high", "critical"] else "INFO",
            "enable_deep_inspection": True if severity in ["high", "critical"] else False
        }
        
        self.logger.info(f"Dynamic reconfiguration for node {node_id}: {config_changes}")
        
        # Add to response history
        self.response_history.append({
            "action": "reconfiguration",
            "node_id": node_id,
            "timestamp": datetime.now().isoformat(),
            "threat_assessment": threat_assessment,
            "config_changes": config_changes
        })
        
        return config_changes
    
    def escalated_alert_system(self, node_id: str, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Escalate alerts based on incident severity"""
        incident_type = incident.get("type", "unknown")
        severity = incident.get("severity", "low")
        confidence = incident.get("confidence", 0.5)
        
        # Determine escalation level
        escalation_mapping = {
            "low": "standard",
            "medium": "elevated",
            "high": "urgent",
            "critical": "immediate"
        }
        
        escalation_level = escalation_mapping.get(severity, "standard")
        
        # Determine notification channels
        notification_channels = []
        if escalation_level == "standard":
            notification_channels = ["email"]
        elif escalation_level == "elevated":
            notification_channels = ["email", "slack"]
        elif escalation_level == "urgent":
            notification_channels = ["email", "slack", "sms"]
        elif escalation_level == "immediate":
            notification_channels = ["email", "sms", "slack", "pager"]
        
        alert_result = {
            "escalation_level": escalation_level,
            "notification_channels": notification_channels,
            "incident_id": f"INC-{int(time.time())}",
            "node_id": node_id,
            "incident": incident,
            "timestamp": datetime.now().isoformat()
        }
        
        # Simulate sending alert (would integrate with actual notification system)
        alert_message = f"Security incident detected on node {node_id}: {incident_type}"
        send_alert(alert_message, notification_channels, severity)
        
        self.logger.critical(f"Escalated alert for node {node_id}: {incident_type} (level: {escalation_level})")
        
        # Add to response history
        self.response_history.append({
            "action": "alert_escalation",
            "node_id": node_id,
            "timestamp": datetime.now().isoformat(),
            "alert_result": alert_result
        })
        
        return alert_result
    
    def _send_alert(self, alert_data: Dict[str, Any]) -> None:
        """Send alert through configured channels (placeholder)"""
        # This would integrate with actual notification systems
        self.logger.info(f"Alert sent: {alert_data['incident_id']} via {alert_data['notification_channels']}")
    
    def adaptive_response_coordination(self, node_id: str, threat_scenario: Dict[str, Any]) -> Dict[str, Any]:
        """Coordinate multiple adaptive response actions"""
        threat_type = threat_scenario.get("type", "unknown")
        severity = threat_scenario.get("severity", "low")
        indicators = threat_scenario.get("indicators", [])
        
        response_plan = {
            "immediate_actions": [],
            "follow_up_actions": [],
            "monitoring_actions": [],
            "coordination_id": f"COORD-{int(time.time())}"
        }
        
        # Immediate actions based on threat type
        if threat_type == "advanced_persistent_threat":
            response_plan["immediate_actions"].extend([
                "quarantine",
                "alert_escalation",
                "forensic_collection",
                "network_isolation"
            ])
            
            response_plan["follow_up_actions"].extend([
                "network_segmentation",
                "threat_hunting",
                "incident_response_team_activation",
                "external_threat_intelligence_sharing"
            ])
        
        elif threat_type == "malware_infection":
            response_plan["immediate_actions"].extend([
                "quarantine",
                "malware_analysis",
                "system_isolation"
            ])
            
            response_plan["follow_up_actions"].extend([
                "system_reimaging",
                "patch_deployment",
                "antivirus_update"
            ])
        
        elif threat_type == "data_exfiltration":
            response_plan["immediate_actions"].extend([
                "network_blocking",
                "data_loss_prevention",
                "forensic_collection"
            ])
            
            response_plan["follow_up_actions"].extend([
                "data_classification_review",
                "access_control_audit",
                "encryption_enforcement"
            ])
        
        # Enhanced monitoring actions
        response_plan["monitoring_actions"] = [
            "continuous_behavioral_monitoring",
            "network_traffic_analysis",
            "system_integrity_monitoring",
            "threat_intelligence_correlation"
        ]
        
        self.logger.info(f"Coordinated response plan for node {node_id}: {response_plan['coordination_id']}")
        
        # Add to response history
        self.response_history.append({
            "action": "response_coordination",
            "node_id": node_id,
            "timestamp": datetime.now().isoformat(),
            "threat_scenario": threat_scenario,
            "response_plan": response_plan
        })
        
        return response_plan
    
    # Advanced Integration Methods
    def analyze_p2p_network_behavior(self, p2p_manager: Any, network_metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze P2P network behavior for security threats"""
        active_connections = network_metrics.get("active_connections", 0)
        data_transfer_rate = network_metrics.get("data_transfer_rate", 0)
        failed_connections = network_metrics.get("failed_connections", 0)
        suspicious_patterns = network_metrics.get("suspicious_patterns", [])
        
        risk_score = 0
        suspicious_indicators = []
        recommendations = []
        
        # Analyze connection patterns
        if active_connections > 200:
            risk_score += 0.3
            suspicious_indicators.append("high_connection_count")
            recommendations.append("Monitor for potential DDoS or botnet activity")
        
        # Analyze data transfer patterns
        if data_transfer_rate > 10000000:  # 10MB/s
            risk_score += 0.2
            suspicious_indicators.append("high_data_transfer")
            recommendations.append("Investigate potential data exfiltration")
        
        # Analyze failed connections
        failure_rate = failed_connections / max(active_connections, 1)
        if failure_rate > 0.1:  # 10% failure rate
            risk_score += 0.2
            suspicious_indicators.append("high_failure_rate")
            recommendations.append("Check for network scanning or brute force attacks")
        
        # Analyze suspicious patterns
        if suspicious_patterns:
            risk_score += 0.3 * len(suspicious_patterns)
            suspicious_indicators.extend(suspicious_patterns)
            recommendations.append("Investigate detected suspicious patterns")
        
        # Determine risk level
        if risk_score >= 0.8:
            risk_level = "critical"
        elif risk_score >= 0.6:
            risk_level = "high"
        elif risk_score >= 0.4:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        analysis = {
            "risk_level": risk_level,
            "risk_score": min(risk_score, 1.0),
            "suspicious_indicators": suspicious_indicators,
            "recommendations": recommendations,
            "network_metrics": network_metrics,
            "analysis_timestamp": datetime.now().isoformat()
        }
        
        self.logger.info(f"P2P network analysis completed: risk level {risk_level}")
        return analysis
    
    def validate_ota_update(self, ota_manager: Any, update_package: Dict[str, Any]) -> Dict[str, Any]:
        """Validate OTA update package for security"""
        version = update_package.get("version", "unknown")
        checksum = update_package.get("checksum", "")
        signature = update_package.get("signature", "")
        size = update_package.get("size", 0)
        source = update_package.get("source", "unknown")
        
        security_checks = {
            "checksum_verified": False,
            "signature_verified": False,
            "source_trusted": False,
            "size_reasonable": False,
            "version_valid": False
        }
        
        # Checksum verification (simplified)
        if checksum and len(checksum) >= 32:  # Minimum hash length
            security_checks["checksum_verified"] = True
        
        # Signature verification (simplified)
        if signature and signature != "invalid_signature":
            security_checks["signature_verified"] = True
        
        # Source trust verification
        trusted_sources = ["trusted_repository", "official_source", "verified_vendor"]
        if source in trusted_sources:
            security_checks["source_trusted"] = True
        
        # Size reasonableness check
        if 1000 <= size <= 100000000:  # 1KB to 100MB
            security_checks["size_reasonable"] = True
        
        # Version validity check (simplified)
        if version and version != "unknown" and "." in version:
            security_checks["version_valid"] = True
        
        # Calculate overall safety
        passed_checks = sum(1 for check in security_checks.values() if check)
        total_checks = len(security_checks)
        safety_score = passed_checks / total_checks
        
        is_safe = safety_score >= 0.8  # 80% of checks must pass
        
        validation_result = {
            "is_safe": is_safe,
            "safety_score": safety_score,
            "security_checks": security_checks,
            "update_package": update_package,
            "validation_timestamp": datetime.now().isoformat()
        }
        
        self.logger.info(f"OTA update validation: {'SAFE' if is_safe else 'UNSAFE'} (score: {safety_score:.2f})")
        return validation_result
    
    def share_threat_intelligence_with_nnis(self, nnis_engine: Any, threat_intelligence: Dict[str, Any]) -> Dict[str, Any]:
        """Share threat intelligence with NNIS system"""
        threat_type = threat_intelligence.get("threat_type", "unknown")
        indicators = threat_intelligence.get("indicators", [])
        confidence = threat_intelligence.get("confidence", 0.5)
        source = threat_intelligence.get("source", "abiss")
        
        # Generate intelligence ID
        intelligence_id = f"TI-{int(time.time())}-{hash(str(threat_intelligence)) % 10000}"
        
        # Prepare intelligence package for NNIS
        intelligence_package = {
            "id": intelligence_id,
            "type": threat_type,
            "indicators": indicators,
            "confidence": confidence,
            "source": source,
            "timestamp": datetime.now().isoformat(),
            "metadata": {
                "sharing_protocol": "ABISS-NNIS-v1.0",
                "format_version": "1.0",
                "classification": "internal"
            }
        }
        
        # Store in local threat intelligence
        self.threat_intelligence.append(intelligence_package)
        
        # Simulate NNIS response
        nnis_response = {
            "acknowledged": True,
            "intelligence_id": intelligence_id,
            "processing_status": "accepted",
            "integration_status": "pending",
            "response_timestamp": datetime.now().isoformat()
        }
        
        sharing_result = {
            "status": "shared",
            "intelligence_id": intelligence_id,
            "nnis_response": nnis_response,
            "intelligence_package": intelligence_package
        }
        
        self.logger.info(f"Threat intelligence shared with NNIS: {intelligence_id}")
        return sharing_result
    
    # Advanced Performance Methods
    def bulk_behavioral_analysis(self, nodes_data: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Process behavioral analysis for multiple nodes efficiently"""
        results = {}
        
        start_time = time.time()
        
        for node_id, data in nodes_data.items():
            try:
                # Calculate risk score
                risk_score = self.calculate_behavioral_score(node_id, data)
                
                # Perform quick anomaly detection
                anomaly_detected = False
                if node_id in self.behavioral_baselines:
                    composite_result = self.detect_composite_anomaly(
                        node_id, data, methods=["statistical"], consensus_threshold=0.5
                    )
                    anomaly_detected = composite_result["is_anomaly"]
                
                results[node_id] = {
                    "risk_score": risk_score,
                    "anomaly_detected": anomaly_detected,
                    "analysis_timestamp": datetime.now().isoformat(),
                    "processing_time_ms": (time.time() - start_time) * 1000
                }
                
            except Exception as e:
                self.logger.error(f"Error analyzing node {node_id}: {e}")
                results[node_id] = {
                    "error": str(e),
                    "risk_score": 0.5,  # Neutral score on error
                    "anomaly_detected": False
                }
        
        total_time = time.time() - start_time
        self.logger.info(f"Bulk analysis completed: {len(nodes_data)} nodes in {total_time:.2f}s")
        
        return results