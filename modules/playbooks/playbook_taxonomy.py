"""
Attack Taxonomy System
Categorizes and defines all attack types with their characteristics
"""

import json
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum


class AttackCategory(Enum):
    """Main attack categories"""
    NETWORK = "Network Attacks"
    AUTHENTICATION = "Authentication Attacks"
    INJECTION = "Injection Attacks"
    MALWARE = "Malware Attacks"
    SOCIAL_ENGINEERING = "Social Engineering"
    DATA_BREACH = "Data Breach Attacks"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DENIAL_OF_SERVICE = "Denial of Service"
    SUPPLY_CHAIN = "Supply Chain Attacks"


class AttackerType(Enum):
    """Types of attackers"""
    SCRIPT_KIDDIE = "Script Kiddie"
    CYBERCRIMINAL = "Cybercriminal"
    APT = "Advanced Persistent Threat"
    INSIDER = "Insider Threat"
    HACKTIVIST = "Hacktivist"


class SeverityLevel(Enum):
    """Attack severity levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class AttackDefinition:
    """Complete definition of an attack type"""
    attack_id: str
    attack_name: str
    category: str
    sub_category: str
    description: str
    typical_attacker: str
    primary_goal: str
    secondary_goals: List[str]
    base_severity: str
    detection_difficulty: str  # EASY, MEDIUM, HARD, VERY_HARD
    prevalence: str  # RARE, UNCOMMON, COMMON, VERY_COMMON
    
    # Technical characteristics
    requires_authentication: bool
    requires_privileges: bool
    network_based: bool
    host_based: bool
    
    # Impact potential
    confidentiality_impact: str  # NONE, LOW, MEDIUM, HIGH
    integrity_impact: str
    availability_impact: str
    
    # Detection signatures
    log_signatures: List[str]
    network_signatures: List[str]
    behavior_signatures: List[str]
    
    # MITRE ATT&CK mapping (optional but professional)
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    
    # References
    cve_references: List[str]
    documentation_links: List[str]


class AttackTaxonomy:
    """Main taxonomy manager"""
    
    def __init__(self):
        self.attacks: Dict[str, AttackDefinition] = {}
        self._load_default_taxonomy()
    
    def _load_default_taxonomy(self):
        """Load all predefined attack definitions"""
        
        # ============================================
        # AUTHENTICATION ATTACKS
        # ============================================
        
        self.register_attack(AttackDefinition(
            attack_id="ATK-AUTH-001",
            attack_name="Brute Force Attack",
            category=AttackCategory.AUTHENTICATION.value,
            sub_category="Credential-based",
            description="Systematic trial of multiple password combinations to gain unauthorized access",
            typical_attacker=AttackerType.SCRIPT_KIDDIE.value,
            primary_goal="Unauthorized access to user accounts",
            secondary_goals=[
                "Data theft",
                "Lateral movement",
                "System compromise",
                "Privilege escalation"
            ],
            base_severity=SeverityLevel.HIGH.value,
            detection_difficulty="EASY",
            prevalence="VERY_COMMON",
            
            requires_authentication=False,
            requires_privileges=False,
            network_based=True,
            host_based=False,
            
            confidentiality_impact="HIGH",
            integrity_impact="MEDIUM",
            availability_impact="LOW",
            
            log_signatures=[
                "Multiple failed login attempts",
                "Rapid authentication requests",
                "Sequential username testing",
                "Common password patterns",
                "Failed auth from single IP"
            ],
            network_signatures=[
                "High frequency of auth packets",
                "Repeated connection attempts",
                "Unusual timing patterns"
            ],
            behavior_signatures=[
                "Failed attempts > 10 in 5 minutes",
                "Success after many failures",
                "Off-hours login activity",
                "Login from unusual location"
            ],
            
            mitre_tactics=["TA0006: Credential Access"],
            mitre_techniques=["T1110: Brute Force", "T1110.001: Password Guessing"],
            
            cve_references=[],
            documentation_links=[
                "https://attack.mitre.org/techniques/T1110/",
                "https://owasp.org/www-community/attacks/Brute_force_attack"
            ]
        ))
        
        self.register_attack(AttackDefinition(
            attack_id="ATK-AUTH-002",
            attack_name="Credential Stuffing",
            category=AttackCategory.AUTHENTICATION.value,
            sub_category="Credential-based",
            description="Using stolen username/password pairs from data breaches to access accounts",
            typical_attacker=AttackerType.CYBERCRIMINAL.value,
            primary_goal="Account takeover using leaked credentials",
            secondary_goals=[
                "Financial fraud",
                "Identity theft",
                "Data exfiltration",
                "Account resale"
            ],
            base_severity=SeverityLevel.CRITICAL.value,
            detection_difficulty="MEDIUM",
            prevalence="COMMON",
            
            requires_authentication=False,
            requires_privileges=False,
            network_based=True,
            host_based=False,
            
            confidentiality_impact="HIGH",
            integrity_impact="HIGH",
            availability_impact="LOW",
            
            log_signatures=[
                "Multiple usernames, single password pattern",
                "Successful login after few attempts",
                "Login from uncommon user agent",
                "Distributed IP sources",
                "Credential validation attempts"
            ],
            network_signatures=[
                "Traffic from proxy/VPN services",
                "Residential proxy usage",
                "Multiple geolocations"
            ],
            behavior_signatures=[
                "Valid credentials from unusual location",
                "Account access from new device",
                "Immediate high-value actions post-login",
                "Multiple account access from single IP"
            ],
            
            mitre_tactics=["TA0006: Credential Access"],
            mitre_techniques=["T1110.004: Credential Stuffing"],
            
            cve_references=[],
            documentation_links=[
                "https://attack.mitre.org/techniques/T1110/004/",
                "https://owasp.org/www-community/attacks/Credential_stuffing"
            ]
        ))
        
        self.register_attack(AttackDefinition(
            attack_id="ATK-AUTH-003",
            attack_name="Password Spraying",
            category=AttackCategory.AUTHENTICATION.value,
            sub_category="Credential-based",
            description="Attempting a few common passwords against many usernames to avoid account lockouts",
            typical_attacker=AttackerType.CYBERCRIMINAL.value,
            primary_goal="Gain access while avoiding detection",
            secondary_goals=[
                "Initial foothold",
                "Account enumeration",
                "Privilege escalation",
                "Lateral movement"
            ],
            base_severity=SeverityLevel.HIGH.value,
            detection_difficulty="HARD",
            prevalence="COMMON",
            
            requires_authentication=False,
            requires_privileges=False,
            network_based=True,
            host_based=False,
            
            confidentiality_impact="HIGH",
            integrity_impact="MEDIUM",
            availability_impact="LOW",
            
            log_signatures=[
                "Multiple usernames, common passwords",
                "Low failure rate per account",
                "Distributed timing (avoids lockouts)",
                "Same password across accounts",
                "Seasonal password patterns (Summer2024!, etc.)"
            ],
            network_signatures=[
                "Slow, steady authentication requests",
                "Multiple source IPs (botnet)",
                "Cloud service origins"
            ],
            behavior_signatures=[
                "1-3 failed attempts per account",
                "Long time between same-user attempts",
                "High number of unique users targeted",
                "Alphabetical username order"
            ],
            
            mitre_tactics=["TA0006: Credential Access"],
            mitre_techniques=["T1110.003: Password Spraying"],
            
            cve_references=[],
            documentation_links=[
                "https://attack.mitre.org/techniques/T1110/003/"
            ]
        ))
        
        # ============================================
        # INJECTION ATTACKS
        # ============================================
        
        self.register_attack(AttackDefinition(
            attack_id="ATK-INJ-001",
            attack_name="SQL Injection",
            category=AttackCategory.INJECTION.value,
            sub_category="Database Injection",
            description="Inserting malicious SQL code into application queries to manipulate database",
            typical_attacker=AttackerType.CYBERCRIMINAL.value,
            primary_goal="Unauthorized database access and data extraction",
            secondary_goals=[
                "Data modification",
                "Authentication bypass",
                "Command execution",
                "Data destruction"
            ],
            base_severity=SeverityLevel.CRITICAL.value,
            detection_difficulty="MEDIUM",
            prevalence="COMMON",
            
            requires_authentication=False,
            requires_privileges=False,
            network_based=True,
            host_based=False,
            
            confidentiality_impact="HIGH",
            integrity_impact="HIGH",
            availability_impact="MEDIUM",
            
            log_signatures=[
                "SQL keywords in parameters",
                "UNION SELECT statements",
                "Database error messages",
                "Encoded SQL payloads",
                "information_schema queries",
                "' OR '1'='1 patterns",
                "Comment sequences (-- or /*)",
                "Stacked queries (;)"
            ],
            network_signatures=[
                "Unusual query string lengths",
                "Base64 encoded parameters",
                "Hex encoded payloads"
            ],
            behavior_signatures=[
                "Multiple error responses",
                "Long query execution times",
                "Large result sets",
                "Unusual database queries",
                "Access to system tables"
            ],
            
            mitre_tactics=["TA0001: Initial Access", "TA0009: Collection"],
            mitre_techniques=["T1190: Exploit Public-Facing Application"],
            
            cve_references=[],
            documentation_links=[
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://portswigger.net/web-security/sql-injection"
            ]
        ))
        
        self.register_attack(AttackDefinition(
            attack_id="ATK-INJ-002",
            attack_name="Cross-Site Scripting (XSS)",
            category=AttackCategory.INJECTION.value,
            sub_category="Client-Side Injection",
            description="Injecting malicious scripts into web pages viewed by other users",
            typical_attacker=AttackerType.CYBERCRIMINAL.value,
            primary_goal="Execute scripts in victim's browser context",
            secondary_goals=[
                "Session hijacking",
                "Credential theft",
                "Defacement",
                "Malware distribution"
            ],
            base_severity=SeverityLevel.HIGH.value,
            detection_difficulty="MEDIUM",
            prevalence="VERY_COMMON",
            
            requires_authentication=False,
            requires_privileges=False,
            network_based=True,
            host_based=False,
            
            confidentiality_impact="MEDIUM",
            integrity_impact="HIGH",
            availability_impact="LOW",
            
            log_signatures=[
                "<script> tags in parameters",
                "JavaScript event handlers",
                "Encoded script payloads",
                "document.cookie access",
                "window.location manipulation"
            ],
            network_signatures=[
                "Unusual characters in URLs",
                "Multiple encoding layers",
                "Script tags in POST data"
            ],
            behavior_signatures=[
                "Persistent script storage",
                "Cookie exfiltration attempts",
                "DOM manipulation",
                "External script loading"
            ],
            
            mitre_tactics=["TA0001: Initial Access", "TA0009: Collection"],
            mitre_techniques=["T1189: Drive-by Compromise"],
            
            cve_references=[],
            documentation_links=[
                "https://owasp.org/www-community/attacks/xss/",
                "https://portswigger.net/web-security/cross-site-scripting"
            ]
        ))
        
        self.register_attack(AttackDefinition(
            attack_id="ATK-INJ-003",
            attack_name="Command Injection",
            category=AttackCategory.INJECTION.value,
            sub_category="OS Command Injection",
            description="Executing arbitrary operating system commands on the server",
            typical_attacker=AttackerType.CYBERCRIMINAL.value,
            primary_goal="Execute system commands for full server compromise",
            secondary_goals=[
                "Data exfiltration",
                "Malware installation",
                "Backdoor creation",
                "Lateral movement"
            ],
            base_severity=SeverityLevel.CRITICAL.value,
            detection_difficulty="MEDIUM",
            prevalence="UNCOMMON",
            
            requires_authentication=False,
            requires_privileges=False,
            network_based=True,
            host_based=True,
            
            confidentiality_impact="HIGH",
            integrity_impact="HIGH",
            availability_impact="HIGH",
            
            log_signatures=[
                "Shell metacharacters (;|&)",
                "System command names",
                "File system commands",
                "Network utility calls",
                "Process execution attempts"
            ],
            network_signatures=[
                "Reverse shell connections",
                "Unusual outbound traffic",
                "Non-standard ports"
            ],
            behavior_signatures=[
                "Unexpected process creation",
                "File system modifications",
                "Network connections from web app",
                "Privilege escalation attempts"
            ],
            
            mitre_tactics=["TA0002: Execution"],
            mitre_techniques=["T1059: Command and Scripting Interpreter"],
            
            cve_references=[],
            documentation_links=[
                "https://owasp.org/www-community/attacks/Command_Injection"
            ]
        ))
        
        # ============================================
        # MALWARE ATTACKS
        # ============================================
        
        self.register_attack(AttackDefinition(
            attack_id="ATK-MAL-001",
            attack_name="Ransomware Attack",
            category=AttackCategory.MALWARE.value,
            sub_category="Encryption Malware",
            description="Encrypting victim's files and demanding payment for decryption key",
            typical_attacker=AttackerType.CYBERCRIMINAL.value,
            primary_goal="Financial extortion through data encryption",
            secondary_goals=[
                "Data destruction",
                "Reputation damage",
                "Business disruption",
                "Double extortion (data leak threat)"
            ],
            base_severity=SeverityLevel.CRITICAL.value,
            detection_difficulty="MEDIUM",
            prevalence="COMMON",
            
            requires_authentication=False,
            requires_privileges=False,
            network_based=False,
            host_based=True,
            
            confidentiality_impact="HIGH",
            integrity_impact="HIGH",
            availability_impact="HIGH",
            
            log_signatures=[
                "Mass file modifications",
                "File extension changes",
                "Ransom note creation",
                "Shadow copy deletion",
                "Backup service termination"
            ],
            network_signatures=[
                "Encryption key negotiation",
                "C2 server communication",
                "Tor network usage",
                "Cryptocurrency payment requests"
            ],
            behavior_signatures=[
                "Rapid file encryption",
                "High CPU/disk usage",
                "Process injection",
                "Registry modifications",
                "Network share enumeration"
            ],
            
            mitre_tactics=["TA0040: Impact"],
            mitre_techniques=["T1486: Data Encrypted for Impact"],
            
            cve_references=[],
            documentation_links=[
                "https://attack.mitre.org/techniques/T1486/"
            ]
        ))
        
        # ============================================
        # DATA BREACH ATTACKS
        # ============================================
        
        self.register_attack(AttackDefinition(
            attack_id="ATK-DATA-001",
            attack_name="Data Exfiltration",
            category=AttackCategory.DATA_BREACH.value,
            sub_category="Data Theft",
            description="Unauthorized copying and transfer of sensitive data out of the organization",
            typical_attacker=AttackerType.APT.value,
            primary_goal="Steal sensitive, valuable, or classified information",
            secondary_goals=[
                "Competitive espionage",
                "Financial gain",
                "Identity theft",
                "Blackmail material"
            ],
            base_severity=SeverityLevel.CRITICAL.value,
            detection_difficulty="HARD",
            prevalence="COMMON",
            
            requires_authentication=True,
            requires_privileges=True,
            network_based=True,
            host_based=True,
            
            confidentiality_impact="HIGH",
            integrity_impact="LOW",
            availability_impact="LOW",
            
            log_signatures=[
                "Large data downloads",
                "Bulk file access",
                "Database dumps",
                "Archive file creation",
                "USB device connections",
                "Cloud upload activity"
            ],
            network_signatures=[
                "Unusual outbound traffic volume",
                "Encrypted channels to external IPs",
                "DNS tunneling",
                "Non-standard protocol usage"
            ],
            behavior_signatures=[
                "After-hours data access",
                "Access to unusual file types",
                "Sequential file access",
                "Failed permission attempts followed by success"
            ],
            
            mitre_tactics=["TA0010: Exfiltration"],
            mitre_techniques=["T1041: Exfiltration Over C2 Channel", "T1567: Exfiltration Over Web Service"],
            
            cve_references=[],
            documentation_links=[
                "https://attack.mitre.org/tactics/TA0010/"
            ]
        ))
        
        # ============================================
        # PRIVILEGE ESCALATION ATTACKS
        # ============================================
        
        self.register_attack(AttackDefinition(
            attack_id="ATK-PRIV-001",
            attack_name="Vertical Privilege Escalation",
            category=AttackCategory.PRIVILEGE_ESCALATION.value,
            sub_category="Permission Abuse",
            description="Gaining higher-level privileges than originally assigned",
            typical_attacker=AttackerType.CYBERCRIMINAL.value,
            primary_goal="Elevate access from user to admin/root",
            secondary_goals=[
                "System compromise",
                "Defense evasion",
                "Persistence",
                "Full control"
            ],
            base_severity=SeverityLevel.CRITICAL.value,
            detection_difficulty="HARD",
            prevalence="COMMON",
            
            requires_authentication=True,
            requires_privileges=False,
            network_based=False,
            host_based=True,
            
            confidentiality_impact="HIGH",
            integrity_impact="HIGH",
            availability_impact="HIGH",
            
            log_signatures=[
                "sudo command usage",
                "User permission changes",
                "Group membership modifications",
                "Service account compromise",
                "Kernel module loading"
            ],
            network_signatures=[],
            behavior_signatures=[
                "Unusual admin actions from regular account",
                "Permission enumeration",
                "Exploit attempts",
                "Binary execution from unusual locations"
            ],
            
            mitre_tactics=["TA0004: Privilege Escalation"],
            mitre_techniques=["T1068: Exploitation for Privilege Escalation"],
            
            cve_references=[],
            documentation_links=[
                "https://attack.mitre.org/tactics/TA0004/"
            ]
        ))
        
        # ============================================
        # DENIAL OF SERVICE
        # ============================================
        
        self.register_attack(AttackDefinition(
            attack_id="ATK-DOS-001",
            attack_name="Distributed Denial of Service (DDoS)",
            category=AttackCategory.DENIAL_OF_SERVICE.value,
            sub_category="Network Flooding",
            description="Overwhelming target with traffic from multiple sources to cause service disruption",
            typical_attacker=AttackerType.HACKTIVIST.value,
            primary_goal="Make services unavailable to legitimate users",
            secondary_goals=[
                "Business disruption",
                "Distraction for other attacks",
                "Reputation damage",
                "Financial losses"
            ],
            base_severity=SeverityLevel.HIGH.value,
            detection_difficulty="EASY",
            prevalence="COMMON",
            
            requires_authentication=False,
            requires_privileges=False,
            network_based=True,
            host_based=False,
            
            confidentiality_impact="NONE",
            integrity_impact="NONE",
            availability_impact="HIGH",
            
            log_signatures=[
                "Spike in connection requests",
                "High volume from single/multiple IPs",
                "Repeated identical requests",
                "Malformed packets",
                "Resource exhaustion"
            ],
            network_signatures=[
                "Traffic from botnets",
                "SYN flood patterns",
                "UDP amplification",
                "Application layer floods"
            ],
            behavior_signatures=[
                "Service degradation",
                "Timeout errors",
                "Memory/CPU saturation",
                "Bandwidth exhaustion"
            ],
            
            mitre_tactics=["TA0040: Impact"],
            mitre_techniques=["T1498: Network Denial of Service"],
            
            cve_references=[],
            documentation_links=[
                "https://attack.mitre.org/techniques/T1498/"
            ]
        ))
    
    def register_attack(self, attack: AttackDefinition):
        """Register a new attack definition"""
        self.attacks[attack.attack_id] = attack
    
    def get_attack(self, attack_id: str) -> Optional[AttackDefinition]:
        """Retrieve attack definition by ID"""
        return self.attacks.get(attack_id)
    
    def get_attacks_by_category(self, category: str) -> List[AttackDefinition]:
        """Get all attacks in a category"""
        return [atk for atk in self.attacks.values() if atk.category == category]
    
    def search_attacks(self, keywords: List[str]) -> List[AttackDefinition]:
        """Search attacks by keywords in name, description, or signatures"""
        results = []
        keywords_lower = [k.lower() for k in keywords]
        
        for attack in self.attacks.values():
            searchable_text = (
                f"{attack.attack_name} {attack.description} "
                f"{' '.join(attack.log_signatures)} "
                f"{' '.join(attack.behavior_signatures)}"
            ).lower()
            
            if any(keyword in searchable_text for keyword in keywords_lower):
                results.append(attack)
        
        return results
    
    def export_to_json(self, filepath: str):
        """Export taxonomy to JSON file"""
        data = {
            attack_id: asdict(attack) 
            for attack_id, attack in self.attacks.items()
        }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def import_from_json(self, filepath: str):
        """Import taxonomy from JSON file"""
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        for attack_id, attack_dict in data.items():
            attack = AttackDefinition(**attack_dict)
            self.register_attack(attack)
    
    def get_statistics(self) -> Dict:
        """Get taxonomy statistics"""
        categories = {}
        severities = {}
        difficulties = {}
        
        for attack in self.attacks.values():
            categories[attack.category] = categories.get(attack.category, 0) + 1
            severities[attack.base_severity] = severities.get(attack.base_severity, 0) + 1
            difficulties[attack.detection_difficulty] = difficulties.get(attack.detection_difficulty, 0) + 1
        
        return {
            'total_attacks': len(self.attacks),
            'categories': categories,
            'severities': severities,
            'detection_difficulties': difficulties
        }


# ============================================
# USAGE EXAMPLE & TESTING
# ============================================

if __name__ == "__main__":
    # Initialize taxonomy
    taxonomy = AttackTaxonomy()
    
    # Test retrieval
    brute_force = taxonomy.get_attack("ATK-AUTH-001")
    print(f"Attack: {brute_force.attack_name}")
    print(f"Severity: {brute_force.base_severity}")
    print(f"Log Signatures: {brute_force.log_signatures[:3]}")
    
    # Test search
    results = taxonomy.search_attacks(["SQL", "injection"])
    print(f"\nFound {len(results)} attacks matching 'SQL injection'")
    
    # Export taxonomy
    taxonomy.export_to_json("playbooks/taxonomy/attack_taxonomy.json")
    print("\n✅ Taxonomy exported to playbooks/taxonomy/attack_taxonomy.json")
    
    # Statistics
    stats = taxonomy.get_statistics()
    print(f"\n📊 Statistics: {stats}")