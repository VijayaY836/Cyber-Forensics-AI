"""
Behavioral Indicators System
Defines detection patterns and thresholds for identifying attack behaviors in logs
"""

from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any
from enum import Enum
import json
import pandas as pd


class IndicatorType(Enum):
    """Types of behavioral indicators"""
    QUANTITATIVE = "quantitative"  # Numeric thresholds
    QUALITATIVE = "qualitative"    # Pattern matching
    TEMPORAL = "temporal"          # Time-based patterns
    CONTEXTUAL = "contextual"      # Situational patterns


class ThreatLevel(Enum):
    """Threat severity levels"""
    NORMAL = "NORMAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class QuantitativeThreshold:
    """Numeric threshold for detection"""
    metric_name: str
    description: str
    
    # Thresholds
    low_threshold: float
    medium_threshold: float
    high_threshold: float
    critical_threshold: float
    
    # Time window for measurement
    time_window_minutes: int
    
    # Detection logic
    comparison_operator: str  # >, <, ==, >=, <=
    aggregation_method: str   # count, sum, avg, max, min
    
    # Context
    applies_to: List[str]  # e.g., ["failed_logins", "authentication_events"]
    filter_conditions: Dict[str, Any]  # Additional filters


@dataclass
class QualitativePattern:
    """Pattern-based detection"""
    pattern_name: str
    description: str
    
    # Pattern matching
    log_field: str
    pattern_type: str  # regex, contains, equals, starts_with, ends_with
    pattern_value: str
    
    # Severity
    base_severity: str
    
    # Context
    must_occur_with: List[str]  # Other patterns that must be present
    increases_severity_if: List[str]  # Patterns that escalate severity
    
    # Examples
    example_matches: List[str]
    example_non_matches: List[str]


@dataclass
class TemporalPattern:
    """Time-based behavioral pattern"""
    pattern_name: str
    description: str
    
    # Timing characteristics
    time_of_day: Optional[tuple]  # (start_hour, end_hour) in 24h format
    day_of_week: Optional[List[str]]  # ["Monday", "Tuesday", ...]
    frequency: str  # high_frequency, low_frequency, burst, sustained
    
    # Rate analysis
    events_per_minute: Optional[tuple]  # (min, max)
    consistent_interval: Optional[int]  # seconds between events (indicates automation)
    
    # Severity
    base_severity: str
    severity_multiplier_off_hours: float
    severity_multiplier_weekend: float


@dataclass
class ContextualIndicator:
    """Situational/contextual detection"""
    indicator_name: str
    description: str
    
    # Context factors
    user_type: Optional[List[str]]  # ["admin", "regular", "service_account"]
    resource_sensitivity: Optional[str]  # low, medium, high, critical
    location_anomaly: bool  # Is unusual location suspicious?
    device_anomaly: bool    # Is new device suspicious?
    
    # Behavioral context
    normal_behavior_baseline: Dict[str, Any]
    deviation_threshold: float  # How different from normal triggers alert
    
    # Severity
    base_severity: str


@dataclass
class BehavioralIndicatorSet:
    """Complete set of indicators for an attack type"""
    indicator_set_id: str
    attack_id: str
    attack_name: str
    
    quantitative_indicators: List[QuantitativeThreshold]
    qualitative_indicators: List[QualitativePattern]
    temporal_indicators: List[TemporalPattern]
    contextual_indicators: List[ContextualIndicator]
    
    # Overall detection
    minimum_indicators_for_detection: int
    confidence_weights: Dict[str, float]  # Weight for each indicator type


class BehavioralIndicatorLibrary:
    """Manages all behavioral indicators"""
    
    def __init__(self):
        self.indicator_sets: Dict[str, BehavioralIndicatorSet] = {}
        self._load_default_indicators()
    
    def _load_default_indicators(self):
        """Load predefined behavioral indicators"""
        
        # ============================================
        # BRUTE FORCE ATTACK INDICATORS
        # ============================================
        
        brute_force_indicators = BehavioralIndicatorSet(
            indicator_set_id="IND-001",
            attack_id="ATK-AUTH-001",
            attack_name="Brute Force Attack",
            
            quantitative_indicators=[
                QuantitativeThreshold(
                    metric_name="failed_login_count",
                    description="Number of failed login attempts",
                    low_threshold=10,
                    medium_threshold=25,
                    high_threshold=50,
                    critical_threshold=100,
                    time_window_minutes=5,
                    comparison_operator=">",
                    aggregation_method="count",
                    applies_to=["authentication_events"],
                    filter_conditions={"result": "FAILED"}
                ),
                
                QuantitativeThreshold(
                    metric_name="failed_login_rate",
                    description="Rate of failed attempts (attempts per minute)",
                    low_threshold=2.0,
                    medium_threshold=5.0,
                    high_threshold=10.0,
                    critical_threshold=20.0,
                    time_window_minutes=1,
                    comparison_operator=">",
                    aggregation_method="count",
                    applies_to=["authentication_events"],
                    filter_conditions={"result": "FAILED"}
                ),
                
                QuantitativeThreshold(
                    metric_name="unique_passwords_attempted",
                    description="Number of different passwords tried",
                    low_threshold=5,
                    medium_threshold=15,
                    high_threshold=30,
                    critical_threshold=50,
                    time_window_minutes=10,
                    comparison_operator=">",
                    aggregation_method="count",
                    applies_to=["authentication_events"],
                    filter_conditions={"result": "FAILED"}
                ),
                
                QuantitativeThreshold(
                    metric_name="success_after_failures",
                    description="Successful login after many failures",
                    low_threshold=10,
                    medium_threshold=25,
                    high_threshold=50,
                    critical_threshold=100,
                    time_window_minutes=30,
                    comparison_operator=">",
                    aggregation_method="count",
                    applies_to=["authentication_events"],
                    filter_conditions={"preceding_failures": True}
                )
            ],
            
            qualitative_indicators=[
                QualitativePattern(
                    pattern_name="sequential_usernames",
                    description="Testing usernames in alphabetical/sequential order",
                    log_field="user",
                    pattern_type="sequential",
                    pattern_value="admin, admin1, admin2, administrator",
                    base_severity="MEDIUM",
                    must_occur_with=["multiple_failed_attempts"],
                    increases_severity_if=["automated_timing"],
                    example_matches=["admin", "admin1", "admin2"],
                    example_non_matches=["john.doe", "alice.smith"]
                ),
                
                QualitativePattern(
                    pattern_name="common_passwords",
                    description="Attempts using common/default passwords",
                    log_field="password_pattern",
                    pattern_type="contains",
                    pattern_value="password, 123456, admin, default",
                    base_severity="MEDIUM",
                    must_occur_with=[],
                    increases_severity_if=["high_attempt_rate"],
                    example_matches=["password123", "admin", "123456"],
                    example_non_matches=["x9$mK!pQ2@vL"]
                ),
                
                QualitativePattern(
                    pattern_name="single_source_ip",
                    description="All attempts from single IP address",
                    log_field="ip_address",
                    pattern_type="equals",
                    pattern_value="same_ip",
                    base_severity="HIGH",
                    must_occur_with=["multiple_failed_attempts"],
                    increases_severity_if=["high_attempt_rate"],
                    example_matches=["45.67.89.10"] * 50,
                    example_non_matches=["192.168.1.1", "192.168.1.2", "192.168.1.3"]
                ),
                
                QualitativePattern(
                    pattern_name="tor_or_vpn_usage",
                    description="Attempts from known anonymization services",
                    log_field="ip_address",
                    pattern_type="matches_list",
                    pattern_value="tor_exit_nodes, vpn_providers",
                    base_severity="HIGH",
                    must_occur_with=[],
                    increases_severity_if=["multiple_failed_attempts"],
                    example_matches=["185.220.101.1", "45.142.120.1"],
                    example_non_matches=["8.8.8.8", "192.168.1.1"]
                )
            ],
            
            temporal_indicators=[
                TemporalPattern(
                    pattern_name="off_hours_activity",
                    description="Login attempts during unusual hours",
                    time_of_day=(22, 6),  # 10 PM to 6 AM
                    day_of_week=None,
                    frequency="high_frequency",
                    events_per_minute=(5, 20),
                    consistent_interval=None,
                    base_severity="MEDIUM",
                    severity_multiplier_off_hours=1.5,
                    severity_multiplier_weekend=1.3
                ),
                
                TemporalPattern(
                    pattern_name="automated_timing",
                    description="Consistent intervals suggesting automated tool",
                    time_of_day=None,
                    day_of_week=None,
                    frequency="sustained",
                    events_per_minute=None,
                    consistent_interval=2,  # Exactly 2 seconds between attempts
                    base_severity="HIGH",
                    severity_multiplier_off_hours=1.0,
                    severity_multiplier_weekend=1.0
                ),
                
                TemporalPattern(
                    pattern_name="burst_activity",
                    description="Sudden spike in authentication attempts",
                    time_of_day=None,
                    day_of_week=None,
                    frequency="burst",
                    events_per_minute=(10, 100),
                    consistent_interval=None,
                    base_severity="HIGH",
                    severity_multiplier_off_hours=1.2,
                    severity_multiplier_weekend=1.2
                )
            ],
            
            contextual_indicators=[
                ContextualIndicator(
                    indicator_name="admin_account_targeted",
                    description="Attempts against privileged accounts",
                    user_type=["admin", "root", "administrator"],
                    resource_sensitivity="critical",
                    location_anomaly=True,
                    device_anomaly=True,
                    normal_behavior_baseline={
                        "typical_login_times": [8, 17],
                        "typical_locations": ["office"],
                        "typical_devices": ["known_workstation"]
                    },
                    deviation_threshold=0.7,
                    base_severity="CRITICAL"
                ),
                
                ContextualIndicator(
                    indicator_name="geographic_anomaly",
                    description="Login from unusual geographic location",
                    user_type=None,
                    resource_sensitivity=None,
                    location_anomaly=True,
                    device_anomaly=False,
                    normal_behavior_baseline={
                        "typical_countries": ["US"],
                        "impossible_travel": False
                    },
                    deviation_threshold=0.8,
                    base_severity="MEDIUM"
                ),
                
                ContextualIndicator(
                    indicator_name="new_device_login",
                    description="Login from previously unseen device/user agent",
                    user_type=None,
                    resource_sensitivity=None,
                    location_anomaly=False,
                    device_anomaly=True,
                    normal_behavior_baseline={
                        "known_devices": [],
                        "device_change_frequency": "low"
                    },
                    deviation_threshold=0.6,
                    base_severity="LOW"
                )
            ],
            
            minimum_indicators_for_detection=2,
            confidence_weights={
                "quantitative": 0.35,
                "qualitative": 0.25,
                "temporal": 0.20,
                "contextual": 0.20
            }
        )
        
        self.register_indicator_set(brute_force_indicators)
        
        # ============================================
        # SQL INJECTION ATTACK INDICATORS
        # ============================================
        
        sql_injection_indicators = BehavioralIndicatorSet(
            indicator_set_id="IND-002",
            attack_id="ATK-INJ-001",
            attack_name="SQL Injection Attack",
            
            quantitative_indicators=[
                QuantitativeThreshold(
                    metric_name="sql_keyword_count",
                    description="Number of SQL keywords in parameters",
                    low_threshold=3,
                    medium_threshold=10,
                    high_threshold=25,
                    critical_threshold=50,
                    time_window_minutes=5,
                    comparison_operator=">",
                    aggregation_method="count",
                    applies_to=["web_requests"],
                    filter_conditions={"has_sql_keywords": True}
                ),
                
                QuantitativeThreshold(
                    metric_name="database_error_rate",
                    description="Frequency of database error responses",
                    low_threshold=5,
                    medium_threshold=15,
                    high_threshold=30,
                    critical_threshold=50,
                    time_window_minutes=10,
                    comparison_operator=">",
                    aggregation_method="count",
                    applies_to=["web_responses"],
                    filter_conditions={"status_code": 500, "error_type": "database"}
                ),
                
                QuantitativeThreshold(
                    metric_name="query_execution_time",
                    description="Unusually long database query times",
                    low_threshold=1.0,
                    medium_threshold=5.0,
                    high_threshold=10.0,
                    critical_threshold=30.0,
                    time_window_minutes=1,
                    comparison_operator=">",
                    aggregation_method="max",
                    applies_to=["database_queries"],
                    filter_conditions={}
                ),
                
                QuantitativeThreshold(
                    metric_name="large_result_sets",
                    description="Queries returning unusually large result sets",
                    low_threshold=1000,
                    medium_threshold=5000,
                    high_threshold=10000,
                    critical_threshold=50000,
                    time_window_minutes=5,
                    comparison_operator=">",
                    aggregation_method="max",
                    applies_to=["database_queries"],
                    filter_conditions={"rows_returned": True}
                )
            ],
            
            qualitative_indicators=[
                QualitativePattern(
                    pattern_name="union_select",
                    description="UNION SELECT statements in parameters",
                    log_field="request_parameters",
                    pattern_type="regex",
                    pattern_value=r"UNION\s+(ALL\s+)?SELECT",
                    base_severity="CRITICAL",
                    must_occur_with=[],
                    increases_severity_if=["information_schema_access"],
                    example_matches=["' UNION SELECT * FROM users--"],
                    example_non_matches=["normal search query"]
                ),
                
                QualitativePattern(
                    pattern_name="sql_comments",
                    description="SQL comment sequences to bypass filters",
                    log_field="request_parameters",
                    pattern_type="contains",
                    pattern_value="--,/*,*/,#",
                    base_severity="HIGH",
                    must_occur_with=[],
                    increases_severity_if=["sql_keywords"],
                    example_matches=["admin'--", "test'/*"],
                    example_non_matches=["normal-url-with-dash"]
                ),
                
                QualitativePattern(
                    pattern_name="information_schema_access",
                    description="Attempts to query database metadata",
                    log_field="query_text",
                    pattern_type="contains",
                    pattern_value="information_schema",
                    base_severity="CRITICAL",
                    must_occur_with=[],
                    increases_severity_if=["union_select"],
                    example_matches=["SELECT * FROM information_schema.tables"],
                    example_non_matches=["SELECT * FROM products"]
                ),
                
                QualitativePattern(
                    pattern_name="tautology",
                    description="Always-true conditions (1=1, 'a'='a')",
                    log_field="request_parameters",
                    pattern_type="regex",
                    pattern_value=r"(1=1|'1'='1'|'a'='a'|OR\s+1=1)",
                    base_severity="HIGH",
                    must_occur_with=[],
                    increases_severity_if=["database_errors"],
                    example_matches=["' OR '1'='1", "admin' OR 1=1--"],
                    example_non_matches=["normal=value"]
                ),
                
                QualitativePattern(
                    pattern_name="encoded_payload",
                    description="Base64 or hex encoded SQL injection attempts",
                    log_field="request_parameters",
                    pattern_type="regex",
                    pattern_value=r"(%[0-9A-F]{2}|base64|0x[0-9A-F]+)",
                    base_severity="HIGH",
                    must_occur_with=["sql_keywords"],
                    increases_severity_if=["multiple_encoding_layers"],
                    example_matches=["%27%20UNION%20SELECT", "0x53454c454354"],
                    example_non_matches=["normal text"]
                )
            ],
            
            temporal_indicators=[
                TemporalPattern(
                    pattern_name="rapid_injection_attempts",
                    description="Multiple injection attempts in quick succession",
                    time_of_day=None,
                    day_of_week=None,
                    frequency="high_frequency",
                    events_per_minute=(5, 30),
                    consistent_interval=None,
                    base_severity="HIGH",
                    severity_multiplier_off_hours=1.3,
                    severity_multiplier_weekend=1.2
                ),
                
                TemporalPattern(
                    pattern_name="systematic_enumeration",
                    description="Methodical testing suggesting manual analysis",
                    time_of_day=None,
                    day_of_week=None,
                    frequency="sustained",
                    events_per_minute=(0.5, 2),
                    consistent_interval=30,
                    base_severity="MEDIUM",
                    severity_multiplier_off_hours=1.0,
                    severity_multiplier_weekend=1.0
                )
            ],
            
            contextual_indicators=[
                ContextualIndicator(
                    indicator_name="sensitive_table_access",
                    description="Queries targeting high-value data tables",
                    user_type=None,
                    resource_sensitivity="critical",
                    location_anomaly=False,
                    device_anomaly=False,
                    normal_behavior_baseline={
                        "typical_tables": ["products", "categories"],
                        "sensitive_tables": ["users", "payments", "credentials"]
                    },
                    deviation_threshold=0.9,
                    base_severity="CRITICAL"
                ),
                
                ContextualIndicator(
                    indicator_name="unauthenticated_injection",
                    description="SQL injection from unauthenticated user",
                    user_type=["anonymous", "guest"],
                    resource_sensitivity=None,
                    location_anomaly=False,
                    device_anomaly=False,
                    normal_behavior_baseline={},
                    deviation_threshold=0.5,
                    base_severity="HIGH"
                )
            ],
            
            minimum_indicators_for_detection=2,
            confidence_weights={
                "quantitative": 0.30,
                "qualitative": 0.40,
                "temporal": 0.15,
                "contextual": 0.15
            }
        )
        
        self.register_indicator_set(sql_injection_indicators)
        
        # ============================================
        # RANSOMWARE ATTACK INDICATORS
        # ============================================
        
        ransomware_indicators = BehavioralIndicatorSet(
            indicator_set_id="IND-003",
            attack_id="ATK-MAL-001",
            attack_name="Ransomware Attack",
            
            quantitative_indicators=[
                QuantitativeThreshold(
                    metric_name="file_modification_rate",
                    description="Rapid mass file modifications",
                    low_threshold=100,
                    medium_threshold=500,
                    high_threshold=1000,
                    critical_threshold=5000,
                    time_window_minutes=5,
                    comparison_operator=">",
                    aggregation_method="count",
                    applies_to=["file_operations"],
                    filter_conditions={"operation": "modify"}
                ),
                
                QuantitativeThreshold(
                    metric_name="file_extension_changes",
                    description="Files being renamed with new extensions",
                    low_threshold=50,
                    medium_threshold=200,
                    high_threshold=500,
                    critical_threshold=1000,
                    time_window_minutes=10,
                    comparison_operator=">",
                    aggregation_method="count",
                    applies_to=["file_operations"],
                    filter_conditions={"extension_changed": True}
                ),
                
                QuantitativeThreshold(
                    metric_name="shadow_copy_deletions",
                    description="Volume shadow copy deletion commands",
                    low_threshold=1,
                    medium_threshold=3,
                    high_threshold=5,
                    critical_threshold=10,
                    time_window_minutes=30,
                    comparison_operator=">",
                    aggregation_method="count",
                    applies_to=["system_commands"],
                    filter_conditions={"command": "vssadmin delete"}
                ),
                
                QuantitativeThreshold(
                    metric_name="cpu_disk_spike",
                    description="Sustained high CPU and disk usage",
                    low_threshold=70,
                    medium_threshold=80,
                    high_threshold=90,
                    critical_threshold=95,
                    time_window_minutes=15,
                    comparison_operator=">",
                    aggregation_method="avg",
                    applies_to=["system_resources"],
                    filter_conditions={"metric": "cpu_and_disk"}
                )
            ],
            
            qualitative_indicators=[
                QualitativePattern(
                    pattern_name="ransom_note_creation",
                    description="Creation of ransom note files",
                    log_field="filename",
                    pattern_type="regex",
                    pattern_value=r"(README|DECRYPT|RANSOM|HOW_TO_DECRYPT|RESTORE_FILES)\.(txt|html)",
                    base_severity="CRITICAL",
                    must_occur_with=[],
                    increases_severity_if=["mass_encryption"],
                    example_matches=["README.txt", "HOW_TO_DECRYPT.html"],
                    example_non_matches=["readme.md", "document.txt"]
                ),
                
                QualitativePattern(
                    pattern_name="encrypted_extension",
                    description="Files with ransomware-specific extensions",
                    log_field="filename",
                    pattern_type="regex",
                    pattern_value=r"\.(encrypted|locked|crypto|crypt|cerber|locky|wannacry)$",
                    base_severity="CRITICAL",
                    must_occur_with=[],
                    increases_severity_if=["mass_file_changes"],
                    example_matches=["file.docx.encrypted", "photo.jpg.locked"],
                    example_non_matches=["document.docx", "image.jpg"]
                ),
                
                QualitativePattern(
                    pattern_name="security_tool_termination",
                    description="Attempts to disable antivirus or security tools",
                    log_field="process_command",
                    pattern_type="contains",
                    pattern_value="taskkill, Stop-Service, sc stop, net stop",
                    base_severity="HIGH",
                    must_occur_with=[],
                    increases_severity_if=["file_encryption"],
                    example_matches=["taskkill /IM MsMpEng.exe", "sc stop WinDefend"],
                    example_non_matches=["normal service restart"]
                ),
                
                QualitativePattern(
                    pattern_name="lateral_movement_tools",
                    description="Use of lateral movement utilities",
                    log_field="process_name",
                    pattern_type="contains",
                    pattern_value="psexec, wmic, powershell, mimikatz",
                    base_severity="HIGH",
                    must_occur_with=[],
                    increases_severity_if=["multiple_host_infection"],
                    example_matches=["psexec.exe", "mimikatz.exe"],
                    example_non_matches=["explorer.exe", "chrome.exe"]
                )
            ],
            
            temporal_indicators=[
                TemporalPattern(
                    pattern_name="encryption_timing",
                    description="Mass encryption during off-hours",
                    time_of_day=(18, 6),
                    day_of_week=["Saturday", "Sunday"],
                    frequency="burst",
                    events_per_minute=None,
                    consistent_interval=None,
                    base_severity="CRITICAL",
                    severity_multiplier_off_hours=1.5,
                    severity_multiplier_weekend=1.8
                ),
                
                TemporalPattern(
                    pattern_name="dwell_time",
                    description="Delay between initial infection and encryption",
                    time_of_day=None,
                    day_of_week=None,
                    frequency="sustained",
                    events_per_minute=None,
                    consistent_interval=None,
                    base_severity="HIGH",
                    severity_multiplier_off_hours=1.0,
                    severity_multiplier_weekend=1.0
                )
            ],
            
            contextual_indicators=[
                ContextualIndicator(
                    indicator_name="network_share_encryption",
                    description="Encryption spreading to network shares",
                    user_type=None,
                    resource_sensitivity="critical",
                    location_anomaly=False,
                    device_anomaly=False,
                    normal_behavior_baseline={
                        "typical_network_activity": "low"
                    },
                    deviation_threshold=0.9,
                    base_severity="CRITICAL"
                ),
                
                ContextualIndicator(
                    indicator_name="backup_system_targeted",
                    description="Ransomware targeting backup systems",
                    user_type=None,
                    resource_sensitivity="critical",
                    location_anomaly=False,
                    device_anomaly=False,
                    normal_behavior_baseline={
                        "backup_access_frequency": "scheduled"
                    },
                    deviation_threshold=0.95,
                    base_severity="CRITICAL"
                )
            ],
            
            minimum_indicators_for_detection=3,
            confidence_weights={
                "quantitative": 0.40,
                "qualitative": 0.35,
                "temporal": 0.15,
                "contextual": 0.10
            }
        )
        
        self.register_indicator_set(ransomware_indicators)
    
    def register_indicator_set(self, indicator_set: BehavioralIndicatorSet):
        """Register an indicator set"""
        self.indicator_sets[indicator_set.indicator_set_id] = indicator_set
    
    def get_indicator_set(self, indicator_set_id: str) -> Optional[BehavioralIndicatorSet]:
        """Get indicator set by ID"""
        return self.indicator_sets.get(indicator_set_id)
    
    def get_indicator_set_by_attack_id(self, attack_id: str) -> Optional[BehavioralIndicatorSet]:
        """Get indicator set by attack taxonomy ID"""
        for ind_set in self.indicator_sets.values():
            if ind_set.attack_id == attack_id:
                return ind_set
        return None
    
    def analyze_logs(self, logs_df: pd.DataFrame, attack_id: str) -> Dict:
        """
        Analyze logs against behavioral indicators
        Returns detection results with confidence scores
        """
        indicator_set = self.get_indicator_set_by_attack_id(attack_id)
        if not indicator_set:
            return {"error": "No indicator set found for attack"}
        
        results = {
            "attack_id": attack_id,
            "attack_name": indicator_set.attack_name,
            "indicators_detected": [],
            "severity": "NORMAL",
            "confidence": 0.0,
            "total_indicators_checked": 0,
            "total_indicators_matched": 0
        }
        
        # This is a simplified example - in production, you'd implement
        # full pattern matching logic for each indicator type
        
        # Example: Check quantitative thresholds
        for indicator in indicator_set.quantitative_indicators:
            results["total_indicators_checked"] += 1
            # Placeholder: In real implementation, calculate actual metrics from logs
            
        # Calculate overall confidence
        if results["total_indicators_checked"] > 0:
            match_rate = results["total_indicators_matched"] / results["total_indicators_checked"]
            results["confidence"] = match_rate
        
        return results
    
    def export_to_json(self, filepath: str):
        """Export indicators to JSON"""
        data = {}
        for ind_id, ind_set in self.indicator_sets.items():
            data[ind_id] = {
                "indicator_set_id": ind_set.indicator_set_id,
                "attack_id": ind_set.attack_id,
                "attack_name": ind_set.attack_name,
                "quantitative_indicators": [asdict(q) for q in ind_set.quantitative_indicators],
                "qualitative_indicators": [asdict(q) for q in ind_set.qualitative_indicators],
                "temporal_indicators": [asdict(t) for t in ind_set.temporal_indicators],
                "contextual_indicators": [asdict(c) for c in ind_set.contextual_indicators],
                "minimum_indicators_for_detection": ind_set.minimum_indicators_for_detection,
                "confidence_weights": ind_set.confidence_weights
            }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def get_statistics(self) -> Dict:
        """Get indicator statistics"""
        stats = {
            "total_indicator_sets": len(self.indicator_sets),
            "indicator_sets": {}
        }
        
        for ind_set in self.indicator_sets.values():
            stats["indicator_sets"][ind_set.indicator_set_id] = {
                "attack_name": ind_set.attack_name,
                "quantitative_count": len(ind_set.quantitative_indicators),
                "qualitative_count": len(ind_set.qualitative_indicators),
                "temporal_count": len(ind_set.temporal_indicators),
                "contextual_count": len(ind_set.contextual_indicators),
                "total_indicators": (
                    len(ind_set.quantitative_indicators) +
                    len(ind_set.qualitative_indicators) +
                    len(ind_set.temporal_indicators) +
                    len(ind_set.contextual_indicators)
                )
            }
        
        return stats


# ============================================
# USAGE & TESTING
# ============================================

if __name__ == "__main__":
    library = BehavioralIndicatorLibrary()
    
    # Test brute force indicators
    print("🎯 Brute Force Attack Indicators")
    bf_indicators = library.get_indicator_set_by_attack_id("ATK-AUTH-001")
    print(f"Quantitative Indicators: {len(bf_indicators.quantitative_indicators)}")
    print(f"Qualitative Indicators: {len(bf_indicators.qualitative_indicators)}")
    print(f"Temporal Indicators: {len(bf_indicators.temporal_indicators)}")
    print(f"Contextual Indicators: {len(bf_indicators.contextual_indicators)}")
    
    # Example threshold
    failed_login_threshold = bf_indicators.quantitative_indicators[0]
    print(f"\n📊 Example Threshold: {failed_login_threshold.metric_name}")
    print(f"  CRITICAL if > {failed_login_threshold.critical_threshold} in {failed_login_threshold.time_window_minutes} min")
    
    # Export
    library.export_to_json("playbooks/indicators/behavioral_indicators.json")
    print("\n✅ Indicators exported!")
    
    # Statistics
    stats = library.get_statistics()
    print(f"\n📊 Statistics:")
    for ind_id, ind_stats in stats["indicator_sets"].items():
        print(f"  {ind_stats['attack_name']}: {ind_stats['total_indicators']} total indicators")