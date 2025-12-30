"""
Attack Timing Patterns System
Defines temporal characteristics, durations, and timing predictions for attacks
"""

from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
from enum import Enum
from datetime import datetime, timedelta
import json


class TimeOfDay(Enum):
    """Time periods"""
    BUSINESS_HOURS = "business_hours"  # 8 AM - 6 PM
    OFF_HOURS = "off_hours"  # 6 PM - 8 AM
    LATE_NIGHT = "late_night"  # 10 PM - 6 AM
    EARLY_MORNING = "early_morning"  # 6 AM - 8 AM


class DayType(Enum):
    """Day classifications"""
    WEEKDAY = "weekday"
    WEEKEND = "weekend"
    HOLIDAY = "holiday"


class AttackSpeed(Enum):
    """Attack execution speed"""
    SLOW = "slow"  # Days to weeks
    MEDIUM = "medium"  # Hours to days
    FAST = "fast"  # Minutes to hours
    LIGHTNING = "lightning"  # Seconds to minutes


@dataclass
class StageTimingProfile:
    """Timing profile for a single attack stage"""
    stage_id: str
    stage_number: int
    stage_name: str
    
    # Duration of this stage
    minimum_duration_minutes: int
    typical_duration_minutes: int
    maximum_duration_minutes: int
    
    # Time until next stage begins
    minimum_delay_to_next: int  # minutes
    typical_delay_to_next: int
    maximum_delay_to_next: int
    
    # Time-of-day preferences
    preferred_time_of_day: List[str]  # When attackers prefer to execute this stage
    avoid_time_of_day: List[str]  # When attackers avoid this stage
    
    # Day preferences
    preferred_days: List[str]
    avoid_days: List[str]
    
    # Speed characteristics
    execution_speed: str  # SLOW, MEDIUM, FAST, LIGHTNING
    
    # Automation level
    is_automated: bool
    automation_affects_timing: bool
    
    # Detection window
    detection_window_minutes: int  # How long defenders have to detect/stop


@dataclass
class AttackTimeline:
    """Complete timeline for an attack"""
    timeline_id: str
    attack_id: str
    attack_name: str
    
    # Stage timings
    stage_timings: List[StageTimingProfile]
    
    # Overall attack duration
    minimum_total_duration_minutes: int
    typical_total_duration_minutes: int
    maximum_total_duration_minutes: int
    
    # Overall speed
    attack_speed_category: str
    
    # Critical timing windows
    critical_decision_points: List[Dict]  # Key moments where attack can be stopped
    point_of_no_return_stage: int  # After this stage, very hard to stop
    point_of_no_return_time_minutes: int  # Time to reach point of no return
    
    # Time-based patterns
    preferred_start_times: List[str]  # When attacks typically start
    peak_activity_periods: List[str]  # When most intense activity occurs
    
    # Dwell time
    typical_dwell_time_minutes: Optional[int]  # Time between initial compromise and main attack


@dataclass
class TemporalIndicators:
    """Time-based indicators that suggest attack in progress"""
    indicator_name: str
    description: str
    
    # What to look for
    time_pattern: str  # consistent_intervals, burst, sustained, sporadic
    frequency: str  # high, medium, low
    
    # Specific timing characteristics
    events_per_minute: Optional[Tuple[float, float]]  # (min, max)
    consistent_interval_seconds: Optional[int]  # Exact interval suggests automation
    
    # Unusual timing flags
    off_hours_multiplier: float  # How much more suspicious during off-hours
    weekend_multiplier: float
    holiday_multiplier: float
    
    # Detection
    severity_if_detected: str


@dataclass
class AttackSpeedProfile:
    """How quickly different attacker types execute attacks"""
    attacker_type: str
    speed_category: str
    
    # Stage duration multipliers
    reconnaissance_multiplier: float
    exploitation_multiplier: float
    post_exploitation_multiplier: float
    
    # Typical total time
    typical_attack_duration_minutes: int
    
    # Patience level
    gives_up_after_minutes: Optional[int]  # Time before attacker abandons attempt
    retry_attempts: int  # How many times they retry failed stages


@dataclass
class TimingPatternSet:
    """Complete set of timing patterns for an attack"""
    set_id: str
    attack_id: str
    attack_name: str
    
    attack_timeline: AttackTimeline
    temporal_indicators: List[TemporalIndicators]
    speed_profiles: List[AttackSpeedProfile]


class TimingPatternLibrary:
    """Manages all timing patterns"""
    
    def __init__(self):
        self.timing_sets: Dict[str, TimingPatternSet] = {}
        self._load_default_timings()
    
    def _load_default_timings(self):
        """Load predefined timing patterns"""
        
        # ============================================
        # BRUTE FORCE ATTACK TIMING
        # ============================================
        
        brute_force_stage_timings = [
            StageTimingProfile(
                stage_id="BF-STAGE-1",
                stage_number=1,
                stage_name="Reconnaissance",
                
                minimum_duration_minutes=5,
                typical_duration_minutes=10,
                maximum_duration_minutes=30,
                
                minimum_delay_to_next=2,
                typical_delay_to_next=5,
                maximum_delay_to_next=15,
                
                preferred_time_of_day=[TimeOfDay.OFF_HOURS.value, TimeOfDay.LATE_NIGHT.value],
                avoid_time_of_day=[TimeOfDay.BUSINESS_HOURS.value],
                
                preferred_days=[DayType.WEEKEND.value],
                avoid_days=[],
                
                execution_speed=AttackSpeed.FAST.value,
                
                is_automated=True,
                automation_affects_timing=True,
                
                detection_window_minutes=10
            ),
            
            StageTimingProfile(
                stage_id="BF-STAGE-2",
                stage_number=2,
                stage_name="Password Guessing",
                
                minimum_duration_minutes=10,
                typical_duration_minutes=30,
                maximum_duration_minutes=120,
                
                minimum_delay_to_next=1,
                typical_delay_to_next=2,
                maximum_delay_to_next=5,
                
                preferred_time_of_day=[TimeOfDay.OFF_HOURS.value, TimeOfDay.LATE_NIGHT.value],
                avoid_time_of_day=[TimeOfDay.BUSINESS_HOURS.value],
                
                preferred_days=[DayType.WEEKEND.value, DayType.HOLIDAY.value],
                avoid_days=[],
                
                execution_speed=AttackSpeed.FAST.value,
                
                is_automated=True,
                automation_affects_timing=True,
                
                detection_window_minutes=30
            ),
            
            StageTimingProfile(
                stage_id="BF-STAGE-3",
                stage_number=3,
                stage_name="Successful Authentication",
                
                minimum_duration_minutes=1,
                typical_duration_minutes=2,
                maximum_duration_minutes=5,
                
                minimum_delay_to_next=2,
                typical_delay_to_next=5,
                maximum_delay_to_next=30,
                
                preferred_time_of_day=[TimeOfDay.OFF_HOURS.value],
                avoid_time_of_day=[TimeOfDay.BUSINESS_HOURS.value],
                
                preferred_days=[DayType.WEEKEND.value],
                avoid_days=[],
                
                execution_speed=AttackSpeed.LIGHTNING.value,
                
                is_automated=False,
                automation_affects_timing=False,
                
                detection_window_minutes=5
            ),
            
            StageTimingProfile(
                stage_id="BF-STAGE-4",
                stage_number=4,
                stage_name="Privilege Escalation",
                
                minimum_duration_minutes=5,
                typical_duration_minutes=15,
                maximum_duration_minutes=60,
                
                minimum_delay_to_next=3,
                typical_delay_to_next=10,
                maximum_delay_to_next=30,
                
                preferred_time_of_day=[TimeOfDay.OFF_HOURS.value, TimeOfDay.LATE_NIGHT.value],
                avoid_time_of_day=[TimeOfDay.BUSINESS_HOURS.value],
                
                preferred_days=[DayType.WEEKEND.value],
                avoid_days=[],
                
                execution_speed=AttackSpeed.MEDIUM.value,
                
                is_automated=False,
                automation_affects_timing=False,
                
                detection_window_minutes=15
            ),
            
            StageTimingProfile(
                stage_id="BF-STAGE-5",
                stage_number=5,
                stage_name="Actions on Objectives",
                
                minimum_duration_minutes=5,
                typical_duration_minutes=20,
                maximum_duration_minutes=120,
                
                minimum_delay_to_next=0,
                typical_delay_to_next=0,
                maximum_delay_to_next=0,
                
                preferred_time_of_day=[TimeOfDay.LATE_NIGHT.value],
                avoid_time_of_day=[TimeOfDay.BUSINESS_HOURS.value],
                
                preferred_days=[DayType.WEEKEND.value, DayType.HOLIDAY.value],
                avoid_days=[],
                
                execution_speed=AttackSpeed.MEDIUM.value,
                
                is_automated=False,
                automation_affects_timing=False,
                
                detection_window_minutes=20
            )
        ]
        
        brute_force_timeline = AttackTimeline(
            timeline_id="TIMELINE-001",
            attack_id="ATK-AUTH-001",
            attack_name="Brute Force Attack",
            
            stage_timings=brute_force_stage_timings,
            
            minimum_total_duration_minutes=26,
            typical_total_duration_minutes=82,
            maximum_total_duration_minutes=342,
            
            attack_speed_category=AttackSpeed.FAST.value,
            
            critical_decision_points=[
                {
                    "stage": 2,
                    "time_minutes": 15,
                    "action": "Enable account lockout or CAPTCHA",
                    "effectiveness": "95%"
                },
                {
                    "stage": 3,
                    "time_minutes": 45,
                    "action": "Force MFA on successful login after failures",
                    "effectiveness": "99%"
                },
                {
                    "stage": 4,
                    "time_minutes": 60,
                    "action": "Block IP and reset credentials",
                    "effectiveness": "90%"
                }
            ],
            
            point_of_no_return_stage=4,
            point_of_no_return_time_minutes=60,
            
            preferred_start_times=[
                "22:00-02:00",  # Late night
                "Saturday evenings",
                "Holidays"
            ],
            
            peak_activity_periods=[
                "Stage 2 (Password Guessing) - sustained high activity",
                "Off-hours for stealth"
            ],
            
            typical_dwell_time_minutes=None  # No dwell time, attack is immediate
        )
        
        brute_force_temporal_indicators = [
            TemporalIndicators(
                indicator_name="automated_consistent_timing",
                description="Exactly consistent intervals between attempts",
                time_pattern="consistent_intervals",
                frequency="high",
                events_per_minute=(10, 60),
                consistent_interval_seconds=2,
                off_hours_multiplier=1.5,
                weekend_multiplier=1.3,
                holiday_multiplier=1.4,
                severity_if_detected="HIGH"
            ),
            
            TemporalIndicators(
                indicator_name="rapid_burst",
                description="Sudden spike of authentication attempts",
                time_pattern="burst",
                frequency="high",
                events_per_minute=(20, 100),
                consistent_interval_seconds=None,
                off_hours_multiplier=1.8,
                weekend_multiplier=1.5,
                holiday_multiplier=1.6,
                severity_if_detected="CRITICAL"
            ),
            
            TemporalIndicators(
                indicator_name="sustained_pressure",
                description="Continuous authentication attempts over extended period",
                time_pattern="sustained",
                frequency="medium",
                events_per_minute=(5, 20),
                consistent_interval_seconds=None,
                off_hours_multiplier=1.4,
                weekend_multiplier=1.3,
                holiday_multiplier=1.3,
                severity_if_detected="HIGH"
            )
        ]
        
        brute_force_speed_profiles = [
            AttackSpeedProfile(
                attacker_type="Script Kiddie",
                speed_category=AttackSpeed.FAST.value,
                reconnaissance_multiplier=0.5,  # Faster, less thorough
                exploitation_multiplier=1.0,
                post_exploitation_multiplier=0.3,  # Often skipped
                typical_attack_duration_minutes=30,
                gives_up_after_minutes=15,
                retry_attempts=2
            ),
            
            AttackSpeedProfile(
                attacker_type="Cybercriminal",
                speed_category=AttackSpeed.MEDIUM.value,
                reconnaissance_multiplier=1.0,
                exploitation_multiplier=1.5,
                post_exploitation_multiplier=1.0,
                typical_attack_duration_minutes=90,
                gives_up_after_minutes=60,
                retry_attempts=5
            ),
            
            AttackSpeedProfile(
                attacker_type="APT",
                speed_category=AttackSpeed.SLOW.value,
                reconnaissance_multiplier=3.0,  # Very thorough
                exploitation_multiplier=2.0,
                post_exploitation_multiplier=5.0,  # Extensive
                typical_attack_duration_minutes=1440,  # 24 hours
                gives_up_after_minutes=None,  # Extremely persistent
                retry_attempts=100
            )
        ]
        
        brute_force_timing_set = TimingPatternSet(
            set_id="TIMING-001",
            attack_id="ATK-AUTH-001",
            attack_name="Brute Force Attack",
            attack_timeline=brute_force_timeline,
            temporal_indicators=brute_force_temporal_indicators,
            speed_profiles=brute_force_speed_profiles
        )
        
        self.register_timing_set(brute_force_timing_set)
        
        # ============================================
        # SQL INJECTION ATTACK TIMING
        # ============================================
        
        sql_injection_stage_timings = [
            StageTimingProfile(
                stage_id="SQL-STAGE-1",
                stage_number=1,
                stage_name="Vulnerability Discovery",
                
                minimum_duration_minutes=5,
                typical_duration_minutes=15,
                maximum_duration_minutes=60,
                
                minimum_delay_to_next=2,
                typical_delay_to_next=5,
                maximum_delay_to_next=20,
                
                preferred_time_of_day=[TimeOfDay.OFF_HOURS.value],
                avoid_time_of_day=[],
                
                preferred_days=[],
                avoid_days=[],
                
                execution_speed=AttackSpeed.MEDIUM.value,
                
                is_automated=True,
                automation_affects_timing=True,
                
                detection_window_minutes=15
            ),
            
            StageTimingProfile(
                stage_id="SQL-STAGE-2",
                stage_number=2,
                stage_name="Exploitation",
                
                minimum_duration_minutes=10,
                typical_duration_minutes=30,
                maximum_duration_minutes=180,
                
                minimum_delay_to_next=2,
                typical_delay_to_next=10,
                maximum_delay_to_next=60,
                
                preferred_time_of_day=[TimeOfDay.OFF_HOURS.value, TimeOfDay.LATE_NIGHT.value],
                avoid_time_of_day=[TimeOfDay.BUSINESS_HOURS.value],
                
                preferred_days=[DayType.WEEKEND.value],
                avoid_days=[],
                
                execution_speed=AttackSpeed.MEDIUM.value,
                
                is_automated=False,
                automation_affects_timing=False,
                
                detection_window_minutes=30
            ),
            
            StageTimingProfile(
                stage_id="SQL-STAGE-3",
                stage_number=3,
                stage_name="Data Extraction",
                
                minimum_duration_minutes=5,
                typical_duration_minutes=20,
                maximum_duration_minutes=120,
                
                minimum_delay_to_next=5,
                typical_delay_to_next=15,
                maximum_delay_to_next=60,
                
                preferred_time_of_day=[TimeOfDay.LATE_NIGHT.value],
                avoid_time_of_day=[TimeOfDay.BUSINESS_HOURS.value],
                
                preferred_days=[DayType.WEEKEND.value, DayType.HOLIDAY.value],
                avoid_days=[],
                
                execution_speed=AttackSpeed.FAST.value,
                
                is_automated=False,
                automation_affects_timing=False,
                
                detection_window_minutes=20
            ),
            
            StageTimingProfile(
                stage_id="SQL-STAGE-4",
                stage_number=4,
                stage_name="Persistence & Backdoor",
                
                minimum_duration_minutes=5,
                typical_duration_minutes=15,
                maximum_duration_minutes=60,
                
                minimum_delay_to_next=0,
                typical_delay_to_next=0,
                maximum_delay_to_next=0,
                
                preferred_time_of_day=[TimeOfDay.LATE_NIGHT.value],
                avoid_time_of_day=[TimeOfDay.BUSINESS_HOURS.value],
                
                preferred_days=[DayType.WEEKEND.value, DayType.HOLIDAY.value],
                avoid_days=[],
                
                execution_speed=AttackSpeed.MEDIUM.value,
                
                is_automated=False,
                automation_affects_timing=False,
                
                detection_window_minutes=15
            )
        ]
        
        sql_injection_timeline = AttackTimeline(
            timeline_id="TIMELINE-002",
            attack_id="ATK-INJ-001",
            attack_name="SQL Injection Attack",
            
            stage_timings=sql_injection_stage_timings,
            
            minimum_total_duration_minutes=27,
            typical_total_duration_minutes=95,
            maximum_total_duration_minutes=480,
            
            attack_speed_category=AttackSpeed.MEDIUM.value,
            
            critical_decision_points=[
                {
                    "stage": 1,
                    "time_minutes": 15,
                    "action": "Deploy WAF rules to block SQL injection patterns",
                    "effectiveness": "85%"
                },
                {
                    "stage": 2,
                    "time_minutes": 45,
                    "action": "Block IP and patch vulnerability",
                    "effectiveness": "95%"
                },
                {
                    "stage": 3,
                    "time_minutes": 65,
                    "action": "Isolate database and reset credentials",
                    "effectiveness": "80%"
                }
            ],
            
            point_of_no_return_stage=3,
            point_of_no_return_time_minutes=65,
            
            preferred_start_times=[
                "20:00-06:00",  # Evening to early morning
                "Weekends",
                "Holidays"
            ],
            
            peak_activity_periods=[
                "Stage 2 (Exploitation) - methodical testing",
                "Stage 3 (Data Extraction) - bulk queries"
            ],
            
            typical_dwell_time_minutes=None
        )
        
        sql_injection_temporal_indicators = [
            TemporalIndicators(
                indicator_name="rapid_error_generation",
                description="Quick succession of database error responses",
                time_pattern="burst",
                frequency="high",
                events_per_minute=(5, 30),
                consistent_interval_seconds=None,
                off_hours_multiplier=1.5,
                weekend_multiplier=1.3,
                holiday_multiplier=1.4,
                severity_if_detected="HIGH"
            ),
            
            TemporalIndicators(
                indicator_name="methodical_enumeration",
                description="Slow, systematic testing pattern",
                time_pattern="sustained",
                frequency="low",
                events_per_minute=(0.5, 2),
                consistent_interval_seconds=30,
                off_hours_multiplier=1.3,
                weekend_multiplier=1.2,
                holiday_multiplier=1.3,
                severity_if_detected="MEDIUM"
            ),
            
            TemporalIndicators(
                indicator_name="bulk_data_extraction",
                description="Sustained large query activity",
                time_pattern="sustained",
                frequency="medium",
                events_per_minute=(1, 5),
                consistent_interval_seconds=None,
                off_hours_multiplier=2.0,
                weekend_multiplier=1.8,
                holiday_multiplier=1.9,
                severity_if_detected="CRITICAL"
            )
        ]
        
        sql_injection_speed_profiles = [
            AttackSpeedProfile(
                attacker_type="Script Kiddie",
                speed_category=AttackSpeed.FAST.value,
                reconnaissance_multiplier=0.5,
                exploitation_multiplier=0.8,
                post_exploitation_multiplier=0.3,
                typical_attack_duration_minutes=45,
                gives_up_after_minutes=30,
                retry_attempts=3
            ),
            
            AttackSpeedProfile(
                attacker_type="Cybercriminal",
                speed_category=AttackSpeed.MEDIUM.value,
                reconnaissance_multiplier=1.0,
                exploitation_multiplier=1.5,
                post_exploitation_multiplier=1.0,
                typical_attack_duration_minutes=120,
                gives_up_after_minutes=90,
                retry_attempts=10
            ),
            
            AttackSpeedProfile(
                attacker_type="APT",
                speed_category=AttackSpeed.SLOW.value,
                reconnaissance_multiplier=3.0,
                exploitation_multiplier=2.5,
                post_exploitation_multiplier=4.0,
                typical_attack_duration_minutes=2880,  # 48 hours
                gives_up_after_minutes=None,
                retry_attempts=100
            )
        ]
        
        sql_injection_timing_set = TimingPatternSet(
            set_id="TIMING-002",
            attack_id="ATK-INJ-001",
            attack_name="SQL Injection Attack",
            attack_timeline=sql_injection_timeline,
            temporal_indicators=sql_injection_temporal_indicators,
            speed_profiles=sql_injection_speed_profiles
        )
        
        self.register_timing_set(sql_injection_timing_set)
        
        # ============================================
        # RANSOMWARE ATTACK TIMING
        # ============================================
        
        ransomware_stage_timings = [
            StageTimingProfile(
                stage_id="RANSOMWARE-STAGE-1",
                stage_number=1,
                stage_name="Initial Compromise",
                
                minimum_duration_minutes=1,
                typical_duration_minutes=5,
                maximum_duration_minutes=30,
                
                minimum_delay_to_next=1,
                typical_delay_to_next=3,
                maximum_delay_to_next=10,
                
                preferred_time_of_day=[TimeOfDay.BUSINESS_HOURS.value],  # Phishing works during work hours
                avoid_time_of_day=[],
                
                preferred_days=[DayType.WEEKDAY.value],
                avoid_days=[DayType.WEEKEND.value],
                
                execution_speed=AttackSpeed.LIGHTNING.value,
                
                is_automated=False,
                automation_affects_timing=False,
                
                detection_window_minutes=5
            ),
            
            StageTimingProfile(
                stage_id="RANSOMWARE-STAGE-2",
                stage_number=2,
                stage_name="Malware Execution & Persistence",
                
                minimum_duration_minutes=2,
                typical_duration_minutes=10,
                maximum_duration_minutes=30,
                
                minimum_delay_to_next=10,
                typical_delay_to_next=60,
                maximum_delay_to_next=360,
                
                preferred_time_of_day=[],
                avoid_time_of_day=[],
                
                preferred_days=[],
                avoid_days=[],
                
                execution_speed=AttackSpeed.FAST.value,
                
                is_automated=True,
                automation_affects_timing=True,
                
                detection_window_minutes=10
            ),
            
            StageTimingProfile(
                stage_id="RANSOMWARE-STAGE-3",
                stage_number=3,
                stage_name="Network Reconnaissance",
                
                minimum_duration_minutes=15,
                typical_duration_minutes=60,
                maximum_duration_minutes=480,
                
                minimum_delay_to_next=30,
                typical_delay_to_next=300,
                maximum_delay_to_next=2880,  # Up to 48 hours
                
                preferred_time_of_day=[TimeOfDay.OFF_HOURS.value],
                avoid_time_of_day=[TimeOfDay.BUSINESS_HOURS.value],
                
                preferred_days=[],
                avoid_days=[],
                
                execution_speed=AttackSpeed.MEDIUM.value,
                
                is_automated=True,
                automation_affects_timing=False,
                
                detection_window_minutes=60
            ),
            
            StageTimingProfile(
                stage_id="RANSOMWARE-STAGE-4",
                stage_number=4,
                stage_name="Lateral Movement",
                
                minimum_duration_minutes=60,
                typical_duration_minutes=300,
                maximum_duration_minutes=2880,
                
                minimum_delay_to_next=120,
                typical_delay_to_next=600,
                maximum_delay_to_next=4320,  # Up to 72 hours
                
                preferred_time_of_day=[TimeOfDay.OFF_HOURS.value, TimeOfDay.LATE_NIGHT.value],
                avoid_time_of_day=[TimeOfDay.BUSINESS_HOURS.value],
                
                preferred_days=[],
                avoid_days=[],
                
                execution_speed=AttackSpeed.SLOW.value,
                
                is_automated=False,
                automation_affects_timing=False,
                
                detection_window_minutes=300
            ),
            
            StageTimingProfile(
                stage_id="RANSOMWARE-STAGE-5",
                stage_number=5,
                stage_name="Mass Encryption",
                
                minimum_duration_minutes=30,
                typical_duration_minutes=240,
                maximum_duration_minutes=1440,
                
                minimum_delay_to_next=0,
                typical_delay_to_next=0,
                maximum_delay_to_next=0,
                
                preferred_time_of_day=[TimeOfDay.LATE_NIGHT.value],
                avoid_time_of_day=[TimeOfDay.BUSINESS_HOURS.value],
                
                preferred_days=[DayType.WEEKEND.value, DayType.HOLIDAY.value],  # Maximum impact
                avoid_days=[],
                
                execution_speed=AttackSpeed.FAST.value,
                
                is_automated=True,
                automation_affects_timing=True,
                
                detection_window_minutes=60  # Very little time to stop once started
            )
        ]
        
        ransomware_timeline = AttackTimeline(
            timeline_id="TIMELINE-003",
            attack_id="ATK-MAL-001",
            attack_name="Ransomware Attack",
            
            stage_timings=ransomware_stage_timings,
            
            minimum_total_duration_minutes=108,
            typical_total_duration_minutes=1275,  # ~21 hours
            maximum_total_duration_minutes=9000,  # ~6 days
            
            attack_speed_category=AttackSpeed.MEDIUM.value,
            
            critical_decision_points=[
                {
                    "stage": 2,
                    "time_minutes": 15,
                    "action": "Isolate infected system immediately",
                    "effectiveness": "95%"
                },
                {
                    "stage": 3,
                    "time_minutes": 75,
                    "action": "Segment network and disable lateral movement",
                    "effectiveness": "85%"
                },
                {
                    "stage": 4,
                    "time_minutes": 375,
                    "action": "Disconnect from network, restore from offline backups",
                    "effectiveness": "70%"
                },
                {
                    "stage": 5,
                    "time_minutes": 975,
                    "action": "Emergency shutdown of all systems",
                    "effectiveness": "30%"
                }
            ],
            
            point_of_no_return_stage=5,
            point_of_no_return_time_minutes=975,
            
            preferred_start_times=[
                "Phishing during business hours (Stage 1)",
                "Encryption Friday evening (Stage 5) - delays response over weekend",
                "Holidays for maximum impact"
            ],
            
            peak_activity_periods=[
                "Stage 4 (Lateral Movement) - hours of network activity",
                "Stage 5 (Encryption) - intense CPU/disk activity"
            ],
            
            typical_dwell_time_minutes=720  # 12 hours typical dwell time before encryption
        )
        
        ransomware_temporal_indicators = [
            TemporalIndicators(
                indicator_name="delayed_execution",
                description="Long delay between infection and encryption (dwell time)",
                time_pattern="sporadic",
                frequency="low",
                events_per_minute=None,
                consistent_interval_seconds=None,
                off_hours_multiplier=1.0,
                weekend_multiplier=1.0,
                holiday_multiplier=1.0,
                severity_if_detected="HIGH"
            ),
            
            TemporalIndicators(
                indicator_name="friday_evening_encryption",
                description="Encryption starts Friday evening (weekend delay tactic)",
                time_pattern="burst",
                frequency="high",
                events_per_minute=(50, 200),
                consistent_interval_seconds=None,
                off_hours_multiplier=1.0,
                weekend_multiplier=2.5,  # Significantly more suspicious on weekends
                holiday_multiplier=3.0,
                severity_if_detected="CRITICAL"
            ),
            
            TemporalIndicators(
                indicator_name="off_hours_lateral_movement",
                description="Network scanning and propagation during off-hours",
                time_pattern="sustained",
                frequency="medium",
                events_per_minute=(5, 20),
                consistent_interval_seconds=None,
                off_hours_multiplier=2.0,
                weekend_multiplier=1.5,
                holiday_multiplier=1.8,
                severity_if_detected="HIGH"
            )
        ]
        
        ransomware_speed_profiles = [
            AttackSpeedProfile(
                attacker_type="Opportunistic Ransomware",
                speed_category=AttackSpeed.FAST.value,
                reconnaissance_multiplier=0.3,
                exploitation_multiplier=0.5,
                post_exploitation_multiplier=1.0,
                typical_attack_duration_minutes=120,  # 2 hours
                gives_up_after_minutes=None,  # Automated, doesn't give up
                retry_attempts=0
            ),
            
            AttackSpeedProfile(
                attacker_type="Ransomware Gang (RaaS)",
                speed_category=AttackSpeed.MEDIUM.value,
                reconnaissance_multiplier=1.0,
                exploitation_multiplier=1.0,
                post_exploitation_multiplier=2.0,
                typical_attack_duration_minutes=1440,  # 24 hours
                gives_up_after_minutes=None,
                retry_attempts=10
            ),
            
            AttackSpeedProfile(
                attacker_type="Targeted Ransomware (APT-style)",
                speed_category=AttackSpeed.SLOW.value,
                reconnaissance_multiplier=5.0,
                exploitation_multiplier=3.0,
                post_exploitation_multiplier=10.0,
                typical_attack_duration_minutes=10080,  # 7 days
                gives_up_after_minutes=None,
                retry_attempts=100
            )
        ]
        
        ransomware_timing_set = TimingPatternSet(
            set_id="TIMING-003",
            attack_id="ATK-MAL-001",
            attack_name="Ransomware Attack",
            attack_timeline=ransomware_timeline,
            temporal_indicators=ransomware_temporal_indicators,
            speed_profiles=ransomware_speed_profiles
        )
        
        self.register_timing_set(ransomware_timing_set)
    
    def register_timing_set(self, timing_set: TimingPatternSet):
        """Register a timing pattern set"""
        self.timing_sets[timing_set.set_id] = timing_set
    
    def get_timing_set(self, set_id: str) -> Optional[TimingPatternSet]:
        """Get timing set by ID"""
        return self.timing_sets.get(set_id)
    
    def get_timing_set_by_attack_id(self, attack_id: str) -> Optional[TimingPatternSet]:
        """Get timing set by attack taxonomy ID"""
        for timing_set in self.timing_sets.values():
            if timing_set.attack_id == attack_id:
                return timing_set
        return None
    
    def predict_next_stage_timing(
        self, 
        attack_id: str, 
        current_stage: int,
        current_time: datetime,
        attacker_type: str = "Cybercriminal"
    ) -> Dict:
        """
        Predict when next stage will occur
        """
        timing_set = self.get_timing_set_by_attack_id(attack_id)
        if not timing_set or current_stage >= len(timing_set.attack_timeline.stage_timings):
            return {"error": "Invalid stage or attack ID"}
        
        current_stage_timing = timing_set.attack_timeline.stage_timings[current_stage - 1]
        
        # Get speed profile for attacker type
        speed_profile = None
        for profile in timing_set.speed_profiles:
            if profile.attacker_type == attacker_type:
                speed_profile = profile
                break
        
        if not speed_profile:
            speed_profile = timing_set.speed_profiles[0]  # Default to first profile
        
        # Calculate predicted next stage time
        min_delay = current_stage_timing.minimum_delay_to_next
        typical_delay = current_stage_timing.typical_delay_to_next
        max_delay = current_stage_timing.maximum_delay_to_next
        
        predicted_time_min = current_time + timedelta(minutes=min_delay)
        predicted_time_typical = current_time + timedelta(minutes=typical_delay)
        predicted_time_max = current_time + timedelta(minutes=max_delay)
        
        return {
            "current_stage": current_stage,
            "next_stage": current_stage + 1,
            "predicted_time_window": {
                "earliest": predicted_time_min.strftime("%Y-%m-%d %H:%M:%S"),
                "most_likely": predicted_time_typical.strftime("%Y-%m-%d %H:%M:%S"),
                "latest": predicted_time_max.strftime("%Y-%m-%d %H:%M:%S")
            },
            "minutes_until_next": {
                "min": min_delay,
                "typical": typical_delay,
                "max": max_delay
            },
            "attacker_type": attacker_type,
            "speed_category": speed_profile.speed_category,
            "detection_window_remaining": current_stage_timing.detection_window_minutes
        }
    
    def calculate_time_to_point_of_no_return(
        self,
        attack_id: str,
        current_stage: int,
        current_time: datetime
    ) -> Dict:
        """
        Calculate time remaining until attack reaches point of no return
        """
        timing_set = self.get_timing_set_by_attack_id(attack_id)
        if not timing_set:
            return {"error": "Attack ID not found"}
        
        timeline = timing_set.attack_timeline
        ponr_stage = timeline.point_of_no_return_stage
        
        if current_stage >= ponr_stage:
            return {
                "status": "CRITICAL",
                "message": "Attack has reached or passed point of no return",
                "can_still_stop": False
            }
        
        # Calculate remaining time
        remaining_minutes = 0
        for stage_num in range(current_stage, ponr_stage):
            stage_timing = timeline.stage_timings[stage_num - 1]
            remaining_minutes += stage_timing.typical_duration_minutes
            if stage_num < ponr_stage:
                remaining_minutes += stage_timing.typical_delay_to_next
        
        critical_time = current_time + timedelta(minutes=remaining_minutes)
        
        return {
            "status": "WARNING",
            "can_still_stop": True,
            "current_stage": current_stage,
            "point_of_no_return_stage": ponr_stage,
            "stages_remaining": ponr_stage - current_stage,
            "minutes_remaining": remaining_minutes,
            "critical_time": critical_time.strftime("%Y-%m-%d %H:%M:%S"),
            "recommended_actions": [
                decision["action"] 
                for decision in timeline.critical_decision_points 
                if decision["stage"] >= current_stage
            ]
        }
    
    def export_to_json(self, filepath: str):
        """Export timing patterns to JSON"""
        data = {}
        for set_id, timing_set in self.timing_sets.items():
            data[set_id] = {
                "set_id": timing_set.set_id,
                "attack_id": timing_set.attack_id,
                "attack_name": timing_set.attack_name,
                "attack_timeline": {
                    **asdict(timing_set.attack_timeline),
                    "stage_timings": [asdict(st) for st in timing_set.attack_timeline.stage_timings]
                },
                "temporal_indicators": [asdict(ti) for ti in timing_set.temporal_indicators],
                "speed_profiles": [asdict(sp) for sp in timing_set.speed_profiles]
            }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def get_statistics(self) -> Dict:
        """Get timing statistics"""
        stats = {
            "total_timing_sets": len(self.timing_sets),
            "sets": {}
        }
        
        for timing_set in self.timing_sets.values():
            timeline = timing_set.attack_timeline
            stats["sets"][timing_set.set_id] = {
                "attack_name": timing_set.attack_name,
                "total_stages": len(timeline.stage_timings),
                "typical_duration_hours": timeline.typical_total_duration_minutes / 60,
                "attack_speed": timeline.attack_speed_category,
                "point_of_no_return_stage": timeline.point_of_no_return_stage,
                "detection_windows": [st.detection_window_minutes for st in timeline.stage_timings]
            }
        
        return stats


# ============================================
# USAGE & TESTING
# ============================================

if __name__ == "__main__":
    library = TimingPatternLibrary()
    
    # Test brute force timing
    print("🎯 Brute Force Attack Timing")
    bf_timing = library.get_timing_set_by_attack_id("ATK-AUTH-001")
    print(f"Typical Duration: {bf_timing.attack_timeline.typical_total_duration_minutes} minutes")
    print(f"Attack Speed: {bf_timing.attack_timeline.attack_speed_category}")
    print(f"Point of No Return: Stage {bf_timing.attack_timeline.point_of_no_return_stage}")
    
    # Test timing prediction
    print("\n📊 Next Stage Timing Prediction:")
    current_time = datetime.now()
    prediction = library.predict_next_stage_timing("ATK-AUTH-001", 2, current_time)
    print(f"  Current Stage: {prediction['current_stage']}")
    print(f"  Next Stage: {prediction['next_stage']}")
    print(f"  Most Likely Time: {prediction['predicted_time_window']['most_likely']}")
    print(f"  Minutes Until Next: {prediction['minutes_until_next']['typical']} minutes")
    
    # Test point of no return
    print("\n⏰ Time to Point of No Return:")
    ponr = library.calculate_time_to_point_of_no_return("ATK-AUTH-001", 2, current_time)
    print(f"  Status: {ponr['status']}")
    print(f"  Can Stop: {ponr['can_still_stop']}")
    print(f"  Minutes Remaining: {ponr['minutes_remaining']}")
    print(f"  Recommended Actions: {ponr['recommended_actions'][0]}")
    
    # Export
    library.export_to_json("playbooks/timing/timing_patterns.json")
    print("\n✅ Timing patterns exported!")
    
    # Statistics
    stats = library.get_statistics()
    print(f"\n📊 Statistics:")
    for set_id, set_stats in stats["sets"].items():
        print(f"  {set_stats['attack_name']}:")
        print(f"    Duration: {set_stats['typical_duration_hours']:.1f} hours")
        print(f"    Speed: {set_stats['attack_speed']}")