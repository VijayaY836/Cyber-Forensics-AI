"""
Attack Sequence System
Defines step-by-step progression of attacks with timing and probabilities
"""

from dataclasses import dataclass, asdict
from typing import Dict, List, Optional
from enum import Enum
import json


class StageStatus(Enum):
    """Status of an attack stage"""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class AttackStage:
    """Individual stage in an attack sequence"""
    stage_id: str
    stage_number: int
    stage_name: str
    description: str
    
    # What the attacker does
    attacker_actions: List[str]
    
    # What defenders see in logs
    observable_behaviors: List[str]
    log_signatures: List[str]
    
    # Timing information
    typical_duration_minutes: tuple  # (min, max)
    time_to_next_stage_minutes: tuple  # (min, max) time before next stage starts
    
    # Probability
    success_rate: float  # 0.0 to 1.0
    probability_to_next: float  # Chance attacker proceeds to next stage if this succeeds
    probability_retry: float  # Chance attacker retries if this fails
    probability_abort: float  # Chance attacker gives up if this fails
    
    # Requirements
    requires_previous_stage: bool
    required_capabilities: List[str]  # e.g., ["network_access", "credentials"]
    
    # Detection
    detection_difficulty: str  # EASY, MEDIUM, HARD, VERY_HARD
    detection_signatures: List[str]
    
    # Impact if reached
    severity_if_reached: str  # LOW, MEDIUM, HIGH, CRITICAL


@dataclass
class AttackSequence:
    """Complete attack sequence with all stages"""
    sequence_id: str
    attack_id: str  # Links to AttackTaxonomy
    attack_name: str
    total_stages: int
    
    # All stages in order
    stages: List[AttackStage]
    
    # Overall timing
    minimum_duration_minutes: int
    typical_duration_minutes: int
    maximum_duration_minutes: int
    
    # Attack characteristics
    sophistication_level: str  # LOW, MEDIUM, HIGH, ADVANCED
    stealth_level: str  # LOW, MEDIUM, HIGH
    automation_level: str  # MANUAL, SEMI_AUTOMATED, FULLY_AUTOMATED
    
    # Success factors
    overall_success_rate: float
    critical_stage: int  # Stage number that is most important
    point_of_no_return: int  # Stage after which attack is very hard to stop


class AttackSequenceLibrary:
    """Manages all attack sequences"""
    
    def __init__(self):
        self.sequences: Dict[str, AttackSequence] = {}
        self._load_default_sequences()
    
    def _load_default_sequences(self):
        """Load predefined attack sequences"""
        
        # ============================================
        # BRUTE FORCE ATTACK SEQUENCE
        # ============================================
        
        brute_force_stages = [
            AttackStage(
                stage_id="BF-STAGE-1",
                stage_number=1,
                stage_name="Reconnaissance",
                description="Attacker identifies target and authentication endpoints",
                
                attacker_actions=[
                    "Scan for login pages",
                    "Identify authentication mechanism",
                    "Test for account lockout policies",
                    "Enumerate valid usernames",
                    "Check for rate limiting"
                ],
                
                observable_behaviors=[
                    "Multiple GET requests to login pages",
                    "Testing different URLs (/login, /admin, /auth)",
                    "User enumeration attempts",
                    "Error message analysis",
                    "Testing with known bad credentials"
                ],
                
                log_signatures=[
                    "Multiple 404 errors on admin paths",
                    "Repeated access to login pages",
                    "User enumeration patterns",
                    "Different user agents testing",
                    "Sequential URL probing"
                ],
                
                typical_duration_minutes=(5, 15),
                time_to_next_stage_minutes=(2, 5),
                
                success_rate=0.95,
                probability_to_next=0.90,
                probability_retry=0.08,
                probability_abort=0.02,
                
                requires_previous_stage=False,
                required_capabilities=["network_access"],
                
                detection_difficulty="EASY",
                detection_signatures=[
                    "High volume GET requests",
                    "Sequential URL testing",
                    "Multiple 404s from single IP"
                ],
                
                severity_if_reached="LOW"
            ),
            
            AttackStage(
                stage_id="BF-STAGE-2",
                stage_number=2,
                stage_name="Password Guessing",
                description="Systematic testing of passwords against identified accounts",
                
                attacker_actions=[
                    "Load password dictionary/wordlist",
                    "Configure brute force tool (Hydra, Medusa, custom script)",
                    "Set attack rate to avoid detection",
                    "Begin automated password attempts",
                    "Log successful credentials"
                ],
                
                observable_behaviors=[
                    "High volume of failed login attempts",
                    "Rapid succession of authentication requests",
                    "Common password patterns (admin123, password, etc.)",
                    "Same username, different passwords",
                    "Consistent timing between attempts (automated)"
                ],
                
                log_signatures=[
                    "Failed login attempts > 10 in 5 minutes",
                    "HTTP 401/403 responses in rapid succession",
                    "POST requests to /login endpoint",
                    "Authentication failure events",
                    "Consistent time intervals between attempts (e.g., every 2 seconds)"
                ],
                
                typical_duration_minutes=(10, 30),
                time_to_next_stage_minutes=(1, 3),
                
                success_rate=0.60,
                probability_to_next=0.95,
                probability_retry=0.30,
                probability_abort=0.10,
                
                requires_previous_stage=True,
                required_capabilities=["network_access", "password_wordlist", "brute_force_tool"],
                
                detection_difficulty="EASY",
                detection_signatures=[
                    "Failed logins > threshold",
                    "Automated timing patterns",
                    "Dictionary password attempts"
                ],
                
                severity_if_reached="MEDIUM"
            ),
            
            AttackStage(
                stage_id="BF-STAGE-3",
                stage_number=3,
                stage_name="Successful Authentication",
                description="Attacker gains access with compromised credentials",
                
                attacker_actions=[
                    "Use discovered credentials to login",
                    "Verify access level",
                    "Note session token/cookie",
                    "Test account permissions",
                    "Establish persistence if possible"
                ],
                
                observable_behaviors=[
                    "Successful login after many failures",
                    "Login from unusual IP address",
                    "Login at unusual time (if typical pattern known)",
                    "Different user agent than normal",
                    "Immediate enumeration of resources after login"
                ],
                
                log_signatures=[
                    "Successful authentication (HTTP 200, 302 redirect)",
                    "Session token issued",
                    "Login event after 50+ failed attempts",
                    "New IP for existing user account",
                    "Geographic anomaly in login location"
                ],
                
                typical_duration_minutes=(1, 2),
                time_to_next_stage_minutes=(2, 10),
                
                success_rate=0.85,
                probability_to_next=0.90,
                probability_retry=0.05,
                probability_abort=0.05,
                
                requires_previous_stage=True,
                required_capabilities=["valid_credentials"],
                
                detection_difficulty="MEDIUM",
                detection_signatures=[
                    "Success after many failures",
                    "Anomalous login location",
                    "Unusual login time",
                    "New device/user agent"
                ],
                
                severity_if_reached="HIGH"
            ),
            
            AttackStage(
                stage_id="BF-STAGE-4",
                stage_number=4,
                stage_name="Privilege Escalation Attempt",
                description="Attacker attempts to gain higher privileges",
                
                attacker_actions=[
                    "Test for privilege escalation vulnerabilities",
                    "Attempt to access admin functions",
                    "Try to modify user permissions",
                    "Look for sensitive configuration files",
                    "Test for SQL injection in privileged contexts"
                ],
                
                observable_behaviors=[
                    "Access attempts to admin URLs",
                    "Unusual API calls for privilege checks",
                    "Failed authorization attempts",
                    "Enumeration of user roles/groups",
                    "Attempts to modify account permissions"
                ],
                
                log_signatures=[
                    "403 Forbidden errors on admin resources",
                    "Failed authorization events",
                    "Attempts to access /admin, /root paths",
                    "Permission denied in application logs",
                    "Unauthorized API calls"
                ],
                
                typical_duration_minutes=(5, 15),
                time_to_next_stage_minutes=(3, 10),
                
                success_rate=0.40,
                probability_to_next=0.80,
                probability_retry=0.40,
                probability_abort=0.20,
                
                requires_previous_stage=True,
                required_capabilities=["valid_credentials", "access_to_system"],
                
                detection_difficulty="MEDIUM",
                detection_signatures=[
                    "Authorization failures after successful auth",
                    "Admin resource access attempts",
                    "Permission enumeration"
                ],
                
                severity_if_reached="HIGH"
            ),
            
            AttackStage(
                stage_id="BF-STAGE-5",
                stage_number=5,
                stage_name="Actions on Objectives",
                description="Attacker achieves their goal (data theft, system compromise, etc.)",
                
                attacker_actions=[
                    "Access sensitive data/resources",
                    "Exfiltrate data",
                    "Modify critical records",
                    "Plant backdoor for persistent access",
                    "Cover tracks (delete logs)"
                ],
                
                observable_behaviors=[
                    "Large data queries/downloads",
                    "Access to sensitive tables/files",
                    "Bulk operations (exports, backups)",
                    "Unusual outbound network traffic",
                    "Log deletion attempts"
                ],
                
                log_signatures=[
                    "SELECT * queries on sensitive tables",
                    "Large file downloads",
                    "Data export operations",
                    "Access to customer/financial data",
                    "Log clearing commands",
                    "Backup file creation by non-admin"
                ],
                
                typical_duration_minutes=(5, 20),
                time_to_next_stage_minutes=(0, 0),
                
                success_rate=0.90,
                probability_to_next=0.0,
                probability_retry=0.05,
                probability_abort=0.05,
                
                requires_previous_stage=True,
                required_capabilities=["valid_credentials", "elevated_privileges"],
                
                detection_difficulty="MEDIUM",
                detection_signatures=[
                    "Bulk data access",
                    "Sensitive file downloads",
                    "Unusual data operations",
                    "Log manipulation"
                ],
                
                severity_if_reached="CRITICAL"
            )
        ]
        
        brute_force_sequence = AttackSequence(
            sequence_id="SEQ-001",
            attack_id="ATK-AUTH-001",
            attack_name="Brute Force Attack",
            total_stages=5,
            stages=brute_force_stages,
            minimum_duration_minutes=20,
            typical_duration_minutes=45,
            maximum_duration_minutes=120,
            sophistication_level="LOW",
            stealth_level="LOW",
            automation_level="FULLY_AUTOMATED",
            overall_success_rate=0.18,
            critical_stage=3,
            point_of_no_return=4
        )
        
        self.register_sequence(brute_force_sequence)
        
        # ============================================
        # SQL INJECTION ATTACK SEQUENCE
        # ============================================
        
        sql_injection_stages = [
            AttackStage(
                stage_id="SQL-STAGE-1",
                stage_number=1,
                stage_name="Vulnerability Discovery",
                description="Attacker identifies SQL injection vulnerability",
                
                attacker_actions=[
                    "Scan web application for input fields",
                    "Test parameters with SQL metacharacters",
                    "Observe error messages",
                    "Identify injectable parameters",
                    "Determine database type from errors"
                ],
                
                observable_behaviors=[
                    "URL parameters with special characters",
                    "SQL syntax in query strings",
                    "Database error pages returned",
                    "Testing with quotes, semicolons",
                    "Systematic parameter fuzzing"
                ],
                
                log_signatures=[
                    "Single quote (') in parameters",
                    "SQL keywords in URLs (SELECT, UNION, OR)",
                    "Database error messages in response",
                    "HTTP 500 errors with SQL syntax",
                    "Multiple requests with SQL patterns"
                ],
                
                typical_duration_minutes=(5, 15),
                time_to_next_stage_minutes=(2, 5),
                
                success_rate=0.70,
                probability_to_next=0.95,
                probability_retry=0.20,
                probability_abort=0.05,
                
                requires_previous_stage=False,
                required_capabilities=["network_access", "web_browser_or_tool"],
                
                detection_difficulty="MEDIUM",
                detection_signatures=[
                    "SQL metacharacters in input",
                    "Database errors",
                    "Unusual URL patterns"
                ],
                
                severity_if_reached="LOW"
            ),
            
            AttackStage(
                stage_id="SQL-STAGE-2",
                stage_number=2,
                stage_name="Exploitation",
                description="Attacker crafts and executes SQL injection payload",
                
                attacker_actions=[
                    "Craft SQL injection payload",
                    "Test UNION-based injection",
                    "Enumerate database structure",
                    "Extract table names",
                    "Identify valuable data tables"
                ],
                
                observable_behaviors=[
                    "UNION SELECT queries",
                    "information_schema queries",
                    "Database enumeration attempts",
                    "Hex/Base64 encoded payloads",
                    "Stacked queries (multiple statements)"
                ],
                
                log_signatures=[
                    "UNION SELECT in parameters",
                    "information_schema.tables queries",
                    "SHOW TABLES commands",
                    "Encoded SQL payloads",
                    "Multiple queries in single request"
                ],
                
                typical_duration_minutes=(10, 30),
                time_to_next_stage_minutes=(2, 10),
                
                success_rate=0.75,
                probability_to_next=0.90,
                probability_retry=0.35,
                probability_abort=0.10,
                
                requires_previous_stage=True,
                required_capabilities=["sql_injection_tool", "database_knowledge"],
                
                detection_difficulty="MEDIUM",
                detection_signatures=[
                    "SQL injection patterns",
                    "Schema enumeration",
                    "Database metadata access"
                ],
                
                severity_if_reached="HIGH"
            ),
            
            AttackStage(
                stage_id="SQL-STAGE-3",
                stage_number=3,
                stage_name="Data Extraction",
                description="Attacker exfiltrates sensitive data from database",
                
                attacker_actions=[
                    "Query sensitive tables",
                    "Extract user credentials",
                    "Download customer data",
                    "Retrieve payment information",
                    "Exfiltrate data to external server"
                ],
                
                observable_behaviors=[
                    "Large result sets returned",
                    "Queries on sensitive tables",
                    "SELECT * from critical tables",
                    "Data encoded in responses",
                    "Unusual outbound connections"
                ],
                
                log_signatures=[
                    "SELECT * FROM users/customers/payments",
                    "Large query results (>1000 rows)",
                    "Suspicious table access",
                    "Long query execution times",
                    "Base64 data in responses"
                ],
                
                typical_duration_minutes=(5, 20),
                time_to_next_stage_minutes=(5, 15),
                
                success_rate=0.85,
                probability_to_next=0.70,
                probability_retry=0.10,
                probability_abort=0.05,
                
                requires_previous_stage=True,
                required_capabilities=["working_sql_injection"],
                
                detection_difficulty="MEDIUM",
                detection_signatures=[
                    "Bulk data queries",
                    "Sensitive table access",
                    "Large data transfers"
                ],
                
                severity_if_reached="CRITICAL"
            ),
            
            AttackStage(
                stage_id="SQL-STAGE-4",
                stage_number=4,
                stage_name="Persistence & Backdoor",
                description="Attacker establishes persistent access",
                
                attacker_actions=[
                    "Create rogue admin account",
                    "Modify application code",
                    "Insert web shell",
                    "Create database triggers",
                    "Plant backdoor for re-entry"
                ],
                
                observable_behaviors=[
                    "INSERT INTO users table",
                    "Unexpected admin account creation",
                    "File writes to web directory",
                    "Database trigger creation",
                    "Stored procedure modifications"
                ],
                
                log_signatures=[
                    "INSERT INTO users/admin",
                    "CREATE USER statements",
                    "File system writes",
                    "CREATE TRIGGER commands",
                    "Stored procedure changes"
                ],
                
                typical_duration_minutes=(5, 15),
                time_to_next_stage_minutes=(0, 0),
                
                success_rate=0.50,
                probability_to_next=0.0,
                probability_retry=0.30,
                probability_abort=0.20,
                
                requires_previous_stage=True,
                required_capabilities=["working_sql_injection", "write_privileges"],
                
                detection_difficulty="HARD",
                detection_signatures=[
                    "Unauthorized account creation",
                    "Code modifications",
                    "Database structure changes"
                ],
                
                severity_if_reached="CRITICAL"
            )
        ]
        
        sql_injection_sequence = AttackSequence(
            sequence_id="SEQ-002",
            attack_id="ATK-INJ-001",
            attack_name="SQL Injection Attack",
            total_stages=4,
            stages=sql_injection_stages,
            minimum_duration_minutes=15,
            typical_duration_minutes=35,
            maximum_duration_minutes=90,
            sophistication_level="MEDIUM",
            stealth_level="MEDIUM",
            automation_level="SEMI_AUTOMATED",
            overall_success_rate=0.33,
            critical_stage=2,
            point_of_no_return=3
        )
        
        self.register_sequence(sql_injection_sequence)
        
        # ============================================
        # RANSOMWARE ATTACK SEQUENCE
        # ============================================
        
        ransomware_stages = [
            AttackStage(
                stage_id="RANSOMWARE-STAGE-1",
                stage_number=1,
                stage_name="Initial Compromise",
                description="Malware gains entry through phishing, exploit, or download",
                
                attacker_actions=[
                    "Send phishing email with malicious attachment",
                    "Exploit vulnerability in web application",
                    "Malvertising or drive-by download",
                    "USB drop attack",
                    "Compromise third-party software"
                ],
                
                observable_behaviors=[
                    "Email attachment opened",
                    "Suspicious download",
                    "Exploit attempt",
                    "Macro execution",
                    "Unknown executable launched"
                ],
                
                log_signatures=[
                    "Email with suspicious attachment",
                    "File download from untrusted source",
                    "Macro execution warning",
                    "New process: suspicious.exe",
                    "Exploit attempt in web logs"
                ],
                
                typical_duration_minutes=(1, 5),
                time_to_next_stage_minutes=(1, 3),
                
                success_rate=0.30,
                probability_to_next=0.95,
                probability_retry=0.0,
                probability_abort=0.05,
                
                requires_previous_stage=False,
                required_capabilities=["social_engineering_or_exploit"],
                
                detection_difficulty="MEDIUM",
                detection_signatures=[
                    "Suspicious file execution",
                    "Macro warnings",
                    "Untrusted downloads"
                ],
                
                severity_if_reached="MEDIUM"
            ),
            
            AttackStage(
                stage_id="RANSOMWARE-STAGE-2",
                stage_number=2,
                stage_name="Malware Execution & Persistence",
                description="Ransomware establishes foothold and prepares for encryption",
                
                attacker_actions=[
                    "Execute malware payload",
                    "Disable antivirus/EDR",
                    "Create persistence mechanism",
                    "Delete shadow copies",
                    "Establish command & control connection"
                ],
                
                observable_behaviors=[
                    "Antivirus disabled",
                    "Registry modifications",
                    "Scheduled task creation",
                    "Shadow copy deletion",
                    "Outbound connections to C2 server"
                ],
                
                log_signatures=[
                    "Windows Defender disabled",
                    "vssadmin delete shadows",
                    "Registry key modifications",
                    "New scheduled task",
                    "Connection to suspicious IP"
                ],
                
                typical_duration_minutes=(2, 10),
                time_to_next_stage_minutes=(10, 60),
                
                success_rate=0.85,
                probability_to_next=0.95,
                probability_retry=0.10,
                probability_abort=0.05,
                
                requires_previous_stage=True,
                required_capabilities=["code_execution", "admin_privileges"],
                
                detection_difficulty="MEDIUM",
                detection_signatures=[
                    "Security tool tampering",
                    "Backup deletion",
                    "Persistence mechanisms"
                ],
                
                severity_if_reached="HIGH"
            ),
            
            AttackStage(
                stage_id="RANSOMWARE-STAGE-3",
                stage_number=3,
                stage_name="Network Reconnaissance",
                description="Malware maps network to maximize impact",
                
                attacker_actions=[
                    "Scan local network",
                    "Enumerate network shares",
                    "Discover domain controllers",
                    "Map file servers",
                    "Identify backup systems"
                ],
                
                observable_behaviors=[
                    "Network scanning activity",
                    "SMB enumeration",
                    "Domain controller queries",
                    "File share access",
                    "LDAP queries"
                ],
                
                log_signatures=[
                    "Port scanning from workstation",
                    "Multiple SMB connections",
                    "Net view/net use commands",
                    "LDAP enumeration",
                    "Unusual network discovery activity"
                ],
                
                typical_duration_minutes=(15, 60),
                time_to_next_stage_minutes=(30, 300),
                
                success_rate=0.80,
                probability_to_next=0.90,
                probability_retry=0.15,
                probability_abort=0.05,
                
                requires_previous_stage=True,
                required_capabilities=["network_access", "enumeration_tools"],
                
                detection_difficulty="MEDIUM",
                detection_signatures=[
                    "Internal network scanning",
                    "SMB enumeration",
                    "Discovery commands"
                ],
                
                severity_if_reached="HIGH"
            ),
            
            AttackStage(
                stage_id="RANSOMWARE-STAGE-4",
                stage_number=4,
                stage_name="Lateral Movement",
                description="Ransomware spreads to other systems",
                
                attacker_actions=[
                    "Exploit SMB vulnerabilities",
                    "Use stolen credentials",
                    "Propagate to network shares",
                    "Compromise additional hosts",
                    "Target domain controllers"
                ],
                
                observable_behaviors=[
                    "Credential theft attempts",
                    "Remote execution on other hosts",
                    "Multiple systems infected",
                    "Network share access from multiple IPs",
                    "Unusual authentication activity"
                ],
                
                log_signatures=[
                    "PsExec or similar remote execution",
                    "Multiple failed then successful auths",
                    "Same malware on multiple hosts",
                    "Credential dumping tools",
                    "Privilege escalation attempts"
                ],
                
                typical_duration_minutes=(60, 300),
                time_to_next_stage_minutes=(120, 600),
                
                success_rate=0.70,
                probability_to_next=0.95,
                probability_retry=0.20,
                probability_abort=0.05,
                
                requires_previous_stage=True,
                required_capabilities=["credentials_or_exploits", "network_access"],
                
                detection_difficulty="MEDIUM",
                detection_signatures=[
                    "Lateral movement tools",
                    "Multiple infected hosts",
                    "Credential abuse"
                ],
                
                severity_if_reached="CRITICAL"
            ),
            
            AttackStage(
                stage_id="RANSOMWARE-STAGE-5",
                stage_number=5,
                stage_name="Mass Encryption",
                description="Simultaneous encryption of files across network",
                
                attacker_actions=[
                    "Trigger encryption routine",
                    "Encrypt files on all compromised systems",
                    "Encrypt network shares",
                    "Display ransom note",
                    "Exfiltrate data (double extortion)"
                ],
                
                observable_behaviors=[
                    "Massive file modifications",
                    "File extension changes (.encrypted, .locked)",
                    "CPU/disk usage spike",
                    "Ransom notes appearing",
                    "Files becoming inaccessible"
                ],
                
                log_signatures=[
                    "Mass file write operations",
                    "Rapid file modifications",
                    "Unknown file extensions",
                    "Ransom note files (README.txt)",
                    "Users reporting encrypted files"
                ],
                
                typical_duration_minutes=(30, 240),
                time_to_next_stage_minutes=(0, 0),
                
                success_rate=0.95,
                probability_to_next=0.0,
                probability_retry=0.0,
                probability_abort=0.0,
                
                requires_previous_stage=True,
                required_capabilities=["encryption_key", "file_access"],
                
                detection_difficulty="EASY",
                detection_signatures=[
                    "Mass file encryption",
                    "Ransom notes",
                    "File extension changes",
                    "System unusability"
                ],
                
                severity_if_reached="CRITICAL"
            )
        ]
        
        ransomware_sequence = AttackSequence(
            sequence_id="SEQ-003",
            attack_id="ATK-MAL-001",
            attack_name="Ransomware Attack",
            total_stages=5,
            stages=ransomware_stages,
            minimum_duration_minutes=120,
            typical_duration_minutes=480,
            maximum_duration_minutes=2880,
            sophistication_level="HIGH",
            stealth_level="MEDIUM",
            automation_level="FULLY_AUTOMATED",
            overall_success_rate=0.40,
            critical_stage=4,
            point_of_no_return=5
        )
        
        self.register_sequence(ransomware_sequence)
    
    def register_sequence(self, sequence: AttackSequence):
        """Register an attack sequence"""
        self.sequences[sequence.sequence_id] = sequence
    
    def get_sequence(self, sequence_id: str) -> Optional[AttackSequence]:
        """Get sequence by ID"""
        return self.sequences.get(sequence_id)
    
    def get_sequence_by_attack_id(self, attack_id: str) -> Optional[AttackSequence]:
        """Get sequence by attack taxonomy ID"""
        for seq in self.sequences.values():
            if seq.attack_id == attack_id:
                return seq
        return None
    
    def predict_next_stage(self, sequence_id: str, current_stage: int) -> Optional[Dict]:
        """Predict next stage and timing"""
        sequence = self.get_sequence(sequence_id)
        if not sequence or current_stage >= sequence.total_stages:
            return None
        
        current = sequence.stages[current_stage - 1]
        
        if current_stage < sequence.total_stages:
            next_stage = sequence.stages[current_stage]
            
            return {
                'next_stage': next_stage,
                'probability': current.probability_to_next,
                'estimated_time_minutes': current.time_to_next_stage_minutes,
                'confidence': current.success_rate * current.probability_to_next,
                'can_be_stopped': current_stage < sequence.point_of_no_return,
                'severity': next_stage.severity_if_reached
            }
        
        return None
    
    def export_to_json(self, filepath: str):
        """Export sequences to JSON"""
        data = {}
        for seq_id, seq in self.sequences.items():
            data[seq_id] = {
                **asdict(seq),
                'stages': [asdict(stage) for stage in seq.stages]
            }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def get_statistics(self) -> Dict:
        """Get sequence statistics"""
        return {
            'total_sequences': len(self.sequences),
            'sequences': {
                seq.sequence_id: {
                    'name': seq.attack_name,
                    'stages': seq.total_stages,
                    'success_rate': seq.overall_success_rate,
                    'sophistication': seq.sophistication_level
                }
                for seq in self.sequences.values()
            }
        }


# ============================================
# USAGE & TESTING
# ============================================

if __name__ == "__main__":
    library = AttackSequenceLibrary()
    
    # Test brute force prediction
    print("🎯 Brute Force Attack Sequence")
    bf_seq = library.get_sequence_by_attack_id("ATK-AUTH-001")
    print(f"Total Stages: {bf_seq.total_stages}")
    print(f"Typical Duration: {bf_seq.typical_duration_minutes} minutes")
    
    # Predict next stage
    prediction = library.predict_next_stage("SEQ-001", 2)
    if prediction:
        print(f"\n📊 Prediction after Stage 2:")
        print(f"Next Stage: {prediction['next_stage'].stage_name}")
        print(f"Probability: {prediction['probability']:.0%}")
        print(f"Time Window: {prediction['estimated_time_minutes']} minutes")
        print(f"Can Stop: {prediction['can_be_stopped']}")
    
    # Export
    library.export_to_json("playbooks/sequences/attack_sequences.json")
    print("\n✅ Sequences exported!")
    
    # Statistics
    stats = library.get_statistics()
    print(f"\n📊 Statistics: {stats}")