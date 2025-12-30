"""
Attacker Profiles System
Defines characteristics, behaviors, and patterns of different attacker types
"""

from dataclasses import dataclass, asdict
from typing import Dict, List, Optional
from enum import Enum
import json


class SkillLevel(Enum):
    """Technical skill levels"""
    BEGINNER = "Beginner"
    INTERMEDIATE = "Intermediate"
    ADVANCED = "Advanced"
    EXPERT = "Expert"


class ResourceLevel(Enum):
    """Resource availability"""
    MINIMAL = "Minimal"
    MODERATE = "Moderate"
    SUBSTANTIAL = "Substantial"
    UNLIMITED = "Unlimited"


class Persistence(Enum):
    """How persistent the attacker is"""
    GIVES_UP_QUICKLY = "Gives Up Quickly"
    MODERATE = "Moderate Persistence"
    PERSISTENT = "Persistent"
    EXTREMELY_PERSISTENT = "Extremely Persistent"


@dataclass
class AttackerCharacteristics:
    """Core characteristics of an attacker type"""
    skill_level: str
    resource_level: str
    persistence_level: str
    
    # Technical capabilities
    custom_tool_development: bool
    zero_day_access: bool
    uses_automation: bool
    encryption_capability: bool
    
    # Operational characteristics
    operates_in_groups: bool
    profit_motivated: bool
    ideology_motivated: bool
    state_sponsored: bool
    
    # Behavioral traits
    risk_tolerance: str  # LOW, MEDIUM, HIGH
    patience: str  # LOW, MEDIUM, HIGH
    sophistication: str  # LOW, MEDIUM, HIGH, ADVANCED


@dataclass
class AttackPatterns:
    """How this attacker type typically operates"""
    preferred_attack_types: List[str]
    common_tools: List[str]
    typical_targets: List[str]
    
    # Tactics
    prefers_stealth: bool
    willing_to_be_noisy: bool
    covers_tracks: bool
    uses_obfuscation: bool
    
    # Timing preferences
    preferred_attack_times: List[str]
    average_attack_duration: str
    
    # Success factors
    typical_success_rate: float  # 0.0 to 1.0
    common_failure_reasons: List[str]


@dataclass
class BehavioralIndicators:
    """Behavioral signatures that identify this attacker type"""
    reconnaissance_style: str
    exploitation_style: str
    post_exploitation_behavior: List[str]
    
    # Detection signatures
    log_patterns: List[str]
    network_patterns: List[str]
    timing_patterns: List[str]
    
    # Unique identifiers
    signature_behaviors: List[str]


@dataclass
class DecisionMaking:
    """How this attacker makes decisions during an attack"""
    when_to_proceed: List[str]
    when_to_abort: List[str]
    when_to_retry: List[str]
    
    # Adaptability
    adapts_to_defenses: bool
    changes_tactics: bool
    learns_from_failures: bool
    
    # Risk assessment
    risk_calculation: str  # NONE, BASIC, MODERATE, SOPHISTICATED


@dataclass
class AttackerProfile:
    """Complete profile of an attacker type"""
    profile_id: str
    attacker_type: str
    description: str
    prevalence: str  # How common this type is
    
    characteristics: AttackerCharacteristics
    attack_patterns: AttackPatterns
    behavioral_indicators: BehavioralIndicators
    decision_making: DecisionMaking
    
    # Real-world context
    typical_organizations: List[str]  # Who they typically are
    motivations: List[str]
    end_goals: List[str]
    
    # Examples
    real_world_examples: List[str]
    case_studies: List[str]


class AttackerProfileLibrary:
    """Manages all attacker profiles"""
    
    def __init__(self):
        self.profiles: Dict[str, AttackerProfile] = {}
        self._load_default_profiles()
    
    def _load_default_profiles(self):
        """Load predefined attacker profiles"""
        
        # ============================================
        # SCRIPT KIDDIE PROFILE
        # ============================================
        
        script_kiddie_profile = AttackerProfile(
            profile_id="PROFILE-001",
            attacker_type="Script Kiddie",
            description="Novice attackers using pre-made tools without deep understanding",
            prevalence="VERY_COMMON",  # 30-40% of all attacks
            
            characteristics=AttackerCharacteristics(
                skill_level=SkillLevel.BEGINNER.value,
                resource_level=ResourceLevel.MINIMAL.value,
                persistence_level=Persistence.GIVES_UP_QUICKLY.value,
                
                custom_tool_development=False,
                zero_day_access=False,
                uses_automation=True,
                encryption_capability=False,
                
                operates_in_groups=False,
                profit_motivated=False,
                ideology_motivated=False,
                state_sponsored=False,
                
                risk_tolerance="HIGH",
                patience="LOW",
                sophistication="LOW"
            ),
            
            attack_patterns=AttackPatterns(
                preferred_attack_types=[
                    "Brute Force",
                    "Basic SQL Injection",
                    "DDoS",
                    "Defacement",
                    "Credential Stuffing"
                ],
                
                common_tools=[
                    "Metasploit",
                    "SQLmap",
                    "Hydra",
                    "Nmap",
                    "Burp Suite (free version)",
                    "LOIC/HOIC (DDoS)",
                    "John the Ripper",
                    "Aircrack-ng"
                ],
                
                typical_targets=[
                    "Small businesses",
                    "Personal websites",
                    "Poorly secured services",
                    "Known vulnerable systems",
                    "Random targets of opportunity"
                ],
                
                prefers_stealth=False,
                willing_to_be_noisy=True,
                covers_tracks=False,
                uses_obfuscation=False,
                
                preferred_attack_times=[
                    "After school hours (3 PM - 11 PM)",
                    "Weekends",
                    "No strategic timing"
                ],
                
                average_attack_duration="15-60 minutes",
                
                typical_success_rate=0.10,
                common_failure_reasons=[
                    "Gives up after initial failure",
                    "Basic security stops them",
                    "Lacks troubleshooting skills",
                    "Detection is easy",
                    "Limited tool knowledge"
                ]
            ),
            
            behavioral_indicators=BehavioralIndicators(
                reconnaissance_style="Shallow, obvious scanning",
                exploitation_style="Brute force, trial-and-error",
                post_exploitation_behavior=[
                    "Simple defacement",
                    "Bragging on forums",
                    "No cleanup",
                    "Leaves obvious traces"
                ],
                
                log_patterns=[
                    "Default tool user agents",
                    "Sequential, obvious attempts",
                    "No evasion techniques",
                    "Multiple failed attempts",
                    "Recognizable tool signatures"
                ],
                
                network_patterns=[
                    "Single source IP",
                    "No proxy/VPN usage",
                    "High volume, low sophistication",
                    "Default port scanning patterns"
                ],
                
                timing_patterns=[
                    "Random timing",
                    "No strategic timing",
                    "Consistent with home internet usage patterns"
                ],
                
                signature_behaviors=[
                    "Uses default tool settings",
                    "Doesn't modify exploits",
                    "Gives up quickly on failure",
                    "Attacks well-known vulnerabilities only",
                    "No post-exploitation activity"
                ]
            ),
            
            decision_making=DecisionMaking(
                when_to_proceed=[
                    "Initial scan shows open ports",
                    "Error messages are visible",
                    "Default credentials work"
                ],
                
                when_to_abort=[
                    "First few attempts fail",
                    "Basic security detected",
                    "Tool doesn't work immediately",
                    "Gets bored (10-15 minutes)"
                ],
                
                when_to_retry=[
                    "Found new tool",
                    "Saw tutorial online",
                    "Someone suggested different approach"
                ],
                
                adapts_to_defenses=False,
                changes_tactics=False,
                learns_from_failures=False,
                
                risk_calculation="NONE"
            ),
            
            typical_organizations=[
                "Teenagers",
                "Young adults",
                "Hobbyists",
                "People seeking notoriety"
            ],
            
            motivations=[
                "Learning/curiosity",
                "Proving skills",
                "Peer recognition",
                "Boredom",
                "Thrill-seeking"
            ],
            
            end_goals=[
                "Successful attack (any kind)",
                "Bragging rights",
                "Forum recognition",
                "Learning experience"
            ],
            
            real_world_examples=[
                "Website defacements",
                "Basic DDoS attacks",
                "Random port scanning",
                "Publicly disclosed vulnerability exploitation"
            ],
            
            case_studies=[
                "Anonymous member arrested using LOIC without VPN",
                "Teenager defaces school website using SQLmap",
                "Script kiddie arrested for DDoS using public tools"
            ]
        )
        
        self.register_profile(script_kiddie_profile)
        
        # ============================================
        # CYBERCRIMINAL PROFILE
        # ============================================
        
        cybercriminal_profile = AttackerProfile(
            profile_id="PROFILE-002",
            attacker_type="Cybercriminal",
            description="Profit-motivated attackers with moderate to high skills",
            prevalence="COMMON",  # 40-50% of all attacks
            
            characteristics=AttackerCharacteristics(
                skill_level=SkillLevel.INTERMEDIATE.value,
                resource_level=ResourceLevel.MODERATE.value,
                persistence_level=Persistence.PERSISTENT.value,
                
                custom_tool_development=True,
                zero_day_access=False,
                uses_automation=True,
                encryption_capability=True,
                
                operates_in_groups=True,
                profit_motivated=True,
                ideology_motivated=False,
                state_sponsored=False,
                
                risk_tolerance="MEDIUM",
                patience="MEDIUM",
                sophistication="MEDIUM"
            ),
            
            attack_patterns=AttackPatterns(
                preferred_attack_types=[
                    "Ransomware",
                    "Data theft",
                    "Credential harvesting",
                    "Business Email Compromise",
                    "SQL Injection",
                    "Cryptojacking",
                    "Banking trojans"
                ],
                
                common_tools=[
                    "Custom malware",
                    "Commercial exploit kits",
                    "Ransomware-as-a-Service",
                    "Phishing kits",
                    "Cobalt Strike",
                    "Mimikatz",
                    "PowerShell Empire",
                    "Modified open-source tools"
                ],
                
                typical_targets=[
                    "SMBs with payment data",
                    "Healthcare organizations",
                    "Financial services",
                    "E-commerce sites",
                    "Anyone with valuable data",
                    "Organizations with poor security"
                ],
                
                prefers_stealth=True,
                willing_to_be_noisy=False,
                covers_tracks=True,
                uses_obfuscation=True,
                
                preferred_attack_times=[
                    "Off-hours (to avoid detection)",
                    "Weekends",
                    "Holidays",
                    "Friday evenings (ransomware deployment)"
                ],
                
                average_attack_duration="Hours to days",
                
                typical_success_rate=0.35,
                common_failure_reasons=[
                    "Detected by security tools",
                    "Strong security controls",
                    "Incident response too fast",
                    "Insufficient privileges gained"
                ]
            ),
            
            behavioral_indicators=BehavioralIndicators(
                reconnaissance_style="Thorough, targeted research",
                exploitation_style="Multiple vectors, patient testing",
                post_exploitation_behavior=[
                    "Privilege escalation",
                    "Lateral movement",
                    "Data exfiltration",
                    "Persistence mechanisms",
                    "Some log cleanup",
                    "Monetization focus"
                ],
                
                log_patterns=[
                    "Modified user agents",
                    "Some evasion attempts",
                    "VPN/proxy usage",
                    "Legitimate-looking traffic",
                    "Encrypted communications"
                ],
                
                network_patterns=[
                    "Multiple IPs (VPN rotation)",
                    "Residential proxies",
                    "Encrypted C2 channels",
                    "DNS tunneling",
                    "Legitimate cloud services for C2"
                ],
                
                timing_patterns=[
                    "Strategic timing (off-hours)",
                    "Staged attack progression",
                    "Patience between stages",
                    "Friday evening ransomware deployment"
                ],
                
                signature_behaviors=[
                    "Profit-driven target selection",
                    "Ransom demands",
                    "Data theft before destruction",
                    "Cryptocurrency payment demands",
                    "Professional communication (ransom notes)",
                    "Negotiation willingness"
                ]
            ),
            
            decision_making=DecisionMaking(
                when_to_proceed=[
                    "Weak security detected",
                    "Valuable data identified",
                    "Good profit potential",
                    "Low detection risk",
                    "Vulnerability confirmed"
                ],
                
                when_to_abort=[
                    "Strong security detected",
                    "Active incident response",
                    "Law enforcement attention",
                    "Low value target",
                    "High risk of identification"
                ],
                
                when_to_retry=[
                    "Different attack vector available",
                    "New vulnerability discovered",
                    "Better tools acquired",
                    "Target security weakened"
                ],
                
                adapts_to_defenses=True,
                changes_tactics=True,
                learns_from_failures=True,
                
                risk_calculation="MODERATE"
            ),
            
            typical_organizations=[
                "Organized crime groups",
                "Ransomware gangs (REvil, Conti, LockBit)",
                "RaaS affiliates",
                "Dark web marketplace operators",
                "BEC fraud groups"
            ],
            
            motivations=[
                "Financial profit (primary)",
                "Building reputation",
                "Growing criminal enterprise",
                "Lifestyle funding"
            ],
            
            end_goals=[
                "Ransom payment",
                "Data sale on dark web",
                "Credential theft for fraud",
                "Banking trojan deployment",
                "Cryptojacking for passive income",
                "BEC wire fraud"
            ],
            
            real_world_examples=[
                "REvil ransomware attacks",
                "Colonial Pipeline ransomware",
                "JBS Foods ransomware",
                "BEC attacks costing millions",
                "Magecart credit card skimming"
            ],
            
            case_studies=[
                "REvil gang demanding $70M from Kaseya",
                "Conti ransomware gang internal chat leaks",
                "BEC scam nets $2.3M from real estate firm"
            ]
        )
        
        self.register_profile(cybercriminal_profile)
        
        # ============================================
        # APT (ADVANCED PERSISTENT THREAT) PROFILE
        # ============================================
        
        apt_profile = AttackerProfile(
            profile_id="PROFILE-003",
            attacker_type="Advanced Persistent Threat (APT)",
            description="Nation-state or highly sophisticated actors with unlimited resources",
            prevalence="RARE",  # 5-10% of attacks
            
            characteristics=AttackerCharacteristics(
                skill_level=SkillLevel.EXPERT.value,
                resource_level=ResourceLevel.UNLIMITED.value,
                persistence_level=Persistence.EXTREMELY_PERSISTENT.value,
                
                custom_tool_development=True,
                zero_day_access=True,
                uses_automation=True,
                encryption_capability=True,
                
                operates_in_groups=True,
                profit_motivated=False,
                ideology_motivated=False,
                state_sponsored=True,
                
                risk_tolerance="LOW",
                patience="HIGH",
                sophistication="ADVANCED"
            ),
            
            attack_patterns=AttackPatterns(
                preferred_attack_types=[
                    "Spear phishing",
                    "Supply chain attacks",
                    "Zero-day exploitation",
                    "Long-term espionage",
                    "Advanced malware",
                    "Living off the land (LOTL)",
                    "Fileless attacks"
                ],
                
                common_tools=[
                    "Custom malware frameworks",
                    "Zero-day exploits",
                    "Custom C2 infrastructure",
                    "Legitimate admin tools (abused)",
                    "Advanced rootkits",
                    "Memory-only malware",
                    "Nation-state grade tools"
                ],
                
                typical_targets=[
                    "Government agencies",
                    "Defense contractors",
                    "Critical infrastructure",
                    "Large corporations",
                    "Research institutions",
                    "Political organizations",
                    "Telecommunications",
                    "High-value individuals"
                ],
                
                prefers_stealth=True,
                willing_to_be_noisy=False,
                covers_tracks=True,
                uses_obfuscation=True,
                
                preferred_attack_times=[
                    "Strategic timing aligned with geopolitical events",
                    "Long-term campaigns (months to years)",
                    "Patient observation periods",
                    "Coordinated multi-stage operations"
                ],
                
                average_attack_duration="Months to years",
                
                typical_success_rate=0.85,
                common_failure_reasons=[
                    "Rare detection by advanced threat hunting",
                    "Attribution leading to exposure",
                    "Whistleblower disclosure",
                    "Advanced security controls"
                ]
            ),
            
            behavioral_indicators=BehavioralIndicators(
                reconnaissance_style="Extensive, multi-source intelligence gathering",
                exploitation_style="Surgical precision, minimal footprint",
                post_exploitation_behavior=[
                    "Long-term persistence",
                    "Multiple redundant backdoors",
                    "Extensive lateral movement",
                    "Credential harvesting",
                    "Data staging and slow exfiltration",
                    "Sophisticated log manipulation",
                    "Living off the land techniques",
                    "Regular check-ins over months/years"
                ],
                
                log_patterns=[
                    "Minimal logging footprint",
                    "Legitimate tool usage",
                    "Normal-looking traffic",
                    "Encrypted everything",
                    "Log manipulation/deletion",
                    "Mimics normal admin activity"
                ],
                
                network_patterns=[
                    "Custom C2 protocols",
                    "Encrypted C2 over legitimate channels",
                    "Slow, low-volume exfiltration",
                    "Blends with normal traffic",
                    "Multiple layers of infrastructure",
                    "Compromised third-party servers",
                    "Domain fronting, DNS over HTTPS"
                ],
                
                timing_patterns=[
                    "Extremely patient",
                    "Weeks/months between actions",
                    "Aligns with target's normal activity",
                    "No obvious patterns",
                    "Strategic geopolitical timing"
                ],
                
                signature_behaviors=[
                    "Custom malware never seen before",
                    "Zero-day usage",
                    "Supply chain compromise",
                    "Watering hole attacks",
                    "Highly targeted spear phishing",
                    "No financial motivation",
                    "Specific intelligence targets",
                    "Advanced anti-forensics",
                    "Multiple redundant access methods"
                ]
            ),
            
            decision_making=DecisionMaking(
                when_to_proceed=[
                    "Strategic objective requires action",
                    "Opportunity for high-value intelligence",
                    "Geopolitical situation favorable",
                    "Target vulnerability confirmed",
                    "Low detection probability"
                ],
                
                when_to_abort=[
                    "Compromise detected (burns infrastructure)",
                    "Mission objective achieved",
                    "Geopolitical situation changes",
                    "Risk of attribution too high"
                ],
                
                when_to_retry=[
                    "Always (unlimited resources)",
                    "Different vector",
                    "New vulnerability discovered",
                    "Target still strategically important"
                ],
                
                adapts_to_defenses=True,
                changes_tactics=True,
                learns_from_failures=True,
                
                risk_calculation="SOPHISTICATED"
            ),
            
            typical_organizations=[
                "Nation-state intelligence agencies",
                "Military cyber units",
                "State-sponsored hacking groups",
                "APT groups (APT28, APT29, APT40, Lazarus, etc.)"
            ],
            
            motivations=[
                "Espionage",
                "Intelligence gathering",
                "Intellectual property theft",
                "Geopolitical advantage",
                "Critical infrastructure mapping",
                "Pre-positioning for future conflict",
                "Strategic sabotage capability"
            ],
            
            end_goals=[
                "Long-term intelligence access",
                "Intellectual property theft",
                "Strategic advantage",
                "Critical infrastructure compromise",
                "Political intelligence",
                "Military secrets",
                "Economic espionage",
                "Sabotage preparation"
            ],
            
            real_world_examples=[
                "SolarWinds supply chain attack (APT29/Cozy Bear)",
                "Stuxnet (industrial sabotage)",
                "APT1 (China) - years-long espionage",
                "Equation Group (NSA-linked)",
                "Lazarus Group (North Korea) - Sony, WannaCry"
            ],
            
            case_studies=[
                "SolarWinds: 18,000 organizations compromised via supply chain",
                "APT29: Months-long persistence in government networks",
                "Stuxnet: Multi-year development for precise industrial sabotage"
            ]
        )
        
        self.register_profile(apt_profile)
        
        # ============================================
        # INSIDER THREAT PROFILE
        # ============================================
        
        insider_profile = AttackerProfile(
            profile_id="PROFILE-004",
            attacker_type="Insider Threat",
            description="Malicious or negligent employees with legitimate access",
            prevalence="UNCOMMON",  # 10-15% of incidents
            
            characteristics=AttackerCharacteristics(
                skill_level=SkillLevel.INTERMEDIATE.value,
                resource_level=ResourceLevel.MODERATE.value,
                persistence_level=Persistence.MODERATE.value,
                
                custom_tool_development=False,
                zero_day_access=False,
                uses_automation=False,
                encryption_capability=False,
                
                operates_in_groups=False,
                profit_motivated=True,
                ideology_motivated=False,
                state_sponsored=False,
                
                risk_tolerance="MEDIUM",
                patience="MEDIUM",
                sophistication="LOW"
            ),
            
            attack_patterns=AttackPatterns(
                preferred_attack_types=[
                    "Data exfiltration",
                    "Intellectual property theft",
                    "Sabotage",
                    "Credential abuse",
                    "Privilege misuse",
                    "Data deletion"
                ],
                
                common_tools=[
                    "Legitimate access credentials",
                    "USB drives",
                    "Cloud storage (Dropbox, Google Drive)",
                    "Email (personal accounts)",
                    "File sharing services",
                    "Mobile devices",
                    "Screen capture tools"
                ],
                
                typical_targets=[
                    "Intellectual property",
                    "Customer databases",
                    "Financial records",
                    "Trade secrets",
                    "Employee data",
                    "Source code"
                ],
                
                prefers_stealth=True,
                willing_to_be_noisy=False,
                covers_tracks=True,
                uses_obfuscation=False,
                
                preferred_attack_times=[
                    "During normal work hours (blends in)",
                    "Just before leaving company",
                    "Off-hours (if suspicious)",
                    "Before layoffs/termination"
                ],
                
                average_attack_duration="Days to months",
                
                typical_success_rate=0.60,
                common_failure_reasons=[
                    "DLP (Data Loss Prevention) detection",
                    "Unusual access patterns flagged",
                    "Audit trail review",
                    "Coworker reports"
                ]
            ),
            
            behavioral_indicators=BehavioralIndicators(
                reconnaissance_style="Uses existing knowledge of systems",
                exploitation_style="Abuse of legitimate access",
                post_exploitation_behavior=[
                    "Data downloads",
                    "File copying",
                    "Email forwarding",
                    "Cloud uploads",
                    "USB transfers",
                    "Screen captures",
                    "Printing sensitive documents"
                ],
                
                log_patterns=[
                    "Legitimate credentials used",
                    "Access to unusual resources",
                    "Large data downloads",
                    "After-hours access (if unusual)",
                    "Access to files outside normal duties",
                    "Failed access to restricted areas"
                ],
                
                network_patterns=[
                    "Legitimate internal traffic",
                    "Large file uploads to personal cloud",
                    "USB device connections",
                    "Email to personal accounts",
                    "VPN access at odd times"
                ],
                
                timing_patterns=[
                    "Often during business hours",
                    "Spike before resignation",
                    "After-hours if intentional theft",
                    "During periods of low supervision"
                ],
                
                signature_behaviors=[
                    "Has authorized access (no break-in)",
                    "Knows what's valuable",
                    "Accesses data outside role",
                    "Unusual timing for access",
                    "Transfers to personal accounts/devices",
                    "Often correlated with job dissatisfaction",
                    "May delete data on exit"
                ]
            ),
            
            decision_making=DecisionMaking(
                when_to_proceed=[
                    "Job dissatisfaction",
                    "About to leave company",
                    "Financial pressure",
                    "Approached by competitor/foreign agent",
                    "Opportunity presents itself"
                ],
                
                when_to_abort=[
                    "Increased monitoring noticed",
                    "Fear of consequences",
                    "Change of plans (staying at company)",
                    "Moral conflict"
                ],
                
                when_to_retry=[
                    "If not caught immediately",
                    "At new job (using stolen data)",
                    "If consequences seem unlikely"
                ],
                
                adapts_to_defenses=False,
                changes_tactics=False,
                learns_from_failures=False,
                
                risk_calculation="BASIC"
            ),
            
            typical_organizations=[
                "Disgruntled employees",
                "Employees leaving for competitors",
                "Financially motivated employees",
                "Negligent employees (unintentional)",
                "Recruited by competitors/nation-states"
            ],
            
            motivations=[
                "Financial gain",
                "Revenge/grudge",
                "Career advancement (taking IP to new job)",
                "Recruitment by external parties",
                "Negligence/carelessness"
            ],
            
            end_goals=[
                "Sell data to competitors",
                "Take IP to new job",
                "Sabotage company",
                "Financial compensation from external parties",
                "Personal use of data"
            ],
            
            real_world_examples=[
                "Employee steals customer list before joining competitor",
                "Engineer downloads source code before departure",
                "Finance employee commits fraud",
                "Negligent employee loses laptop with data"
            ],
            
            case_studies=[
                "Tesla employee stole gigabytes of confidential data",
                "GE engineer stole turbine technology for China",
                "Waymo vs Uber: stolen self-driving car secrets"
            ]
        )
        
        self.register_profile(insider_profile)
        
        # ============================================
        # HACKTIVIST PROFILE
        # ============================================
        
        hacktivist_profile = AttackerProfile(
            profile_id="PROFILE-005",
            attacker_type="Hacktivist",
            description="Ideologically motivated attackers seeking to make political/social statements",
            prevalence="UNCOMMON",  # 5-10% of attacks
            
            characteristics=AttackerCharacteristics(
                skill_level=SkillLevel.INTERMEDIATE.value,
                resource_level=ResourceLevel.MODERATE.value,
                persistence_level=Persistence.PERSISTENT.value,
                
                custom_tool_development=False,
                zero_day_access=False,
                uses_automation=True,
                encryption_capability=False,
                
                operates_in_groups=True,
                profit_motivated=False,
                ideology_motivated=True,
                state_sponsored=False,
                
                risk_tolerance="HIGH",
                patience="MEDIUM",
                sophistication="MEDIUM"
            ),
            
            attack_patterns=AttackPatterns(
                preferred_attack_types=[
                    "DDoS",
                    "Website defacement",
                    "Data leaks/doxing",
                    "Account takeovers",
                    "Defacement",
                    "Information warfare"
                ],
                
                common_tools=[
                    "LOIC/HOIC (DDoS)",
                    "SQLmap",
                    "Web shells",
                    "Social media accounts",
                    "Leak platforms (WikiLeaks style)",
                    "Botnet access",
                    "Anonymous communication tools"
                ],
                
                typical_targets=[
                    "Government websites",
                    "Corporate targets (perceived as unethical)",
                    "Political organizations",
                    "Law enforcement",
                    "Organizations opposed to their ideology",
                    "High-profile public figures"
                ],
                
                prefers_stealth=False,
                willing_to_be_noisy=True,
                covers_tracks=True,
                uses_obfuscation=True,
                
                preferred_attack_times=[
                    "Coordinated campaigns around events",
                    "Political anniversaries",
                    "In response to news events",
                    "Publicized operation dates"
                ],
                
                average_attack_duration="Hours to days",
                
                typical_success_rate=0.40,
                common_failure_reasons=[
                    "Law enforcement action",
                    "Poor operational security",
                    "Internal group conflicts",
                    "Target security too strong"
                ]
            ),
            
            behavioral_indicators=BehavioralIndicators(
                reconnaissance_style="Public research, OSINT",
                exploitation_style="Loud and public attacks",
                post_exploitation_behavior=[
                    "Public data leaks",
                    "Website defacement with messages",
                    "Social media announcements",
                    "Press releases",
                    "DDoS for disruption",
                    "Doxing individuals",
                    "Manifesto publication"
                ],
                
                log_patterns=[
                    "Mass traffic (DDoS)",
                    "SQL injection attempts",
                    "Defacement indicators",
                    "Data exfiltration",
                    "Obvious attack patterns"
                ],
                
                network_patterns=[
                    "DDoS traffic from botnets",
                    "Tor usage",
                    "VPN usage",
                    "Distributed sources",
                    "Coordinated timing"
                ],
                
                timing_patterns=[
                    "Coordinated operations",
                    "Event-driven timing",
                    "Announced operations",
                    "Political calendar alignment"
                ],
                
                signature_behaviors=[
                    "Public announcements of attacks",
                    "Political/ideological messaging",
                    "Defacement with manifesto",
                    "Data leaks for exposure",
                    "Social media presence",
                    "Coordination with news cycle",
                    "Claims responsibility",
                    "Seeks publicity"
                ]
            ),
            
            decision_making=DecisionMaking(
                when_to_proceed=[
                    "Target opposes ideology",
                    "Public event to leverage",
                    "Political momentum",
                    "Group consensus",
                    "Media attention available"
                ],
                
                when_to_abort=[
                    "Law enforcement pressure",
                    "Public backlash",
                    "Internal disagreement",
                    "Risk too high"
                ],
                
                when_to_retry=[
                    "Ideology still opposed",
                    "New opportunity arises",
                    "Group reformation",
                    "Renewed public interest"
                ],
                
                adapts_to_defenses=True,
                changes_tactics=True,
                learns_from_failures=True,
                
                risk_calculation="BASIC"
            ),
            
            typical_organizations=[
                "Anonymous",
                "LulzSec",
                "Cyber Caliphate",
                "Syrian Electronic Army",
                "Loose collectives",
                "Individual activists"
            ],
            
            motivations=[
                "Political ideology",
                "Social justice",
                "Anti-corporate sentiment",
                "Freedom of information",
                "Religious/cultural beliefs",
                "Environmental activism",
                "Anti-government sentiment"
            ],
            
            end_goals=[
                "Public awareness of issue",
                "Embarrass target",
                "Disrupt operations",
                "Leak information",
                "Political change",
                "Damage reputation",
                "Demonstrate vulnerability"
            ],
            
            real_world_examples=[
                "Anonymous - Operation Payback (against anti-piracy orgs)",
                "LulzSec - Sony Pictures hack",
                "Syrian Electronic Army - media outlet hacks",
                "Anonymous - ISIS accounts takedown"
            ],
            
            case_studies=[
                "Operation Payback: Coordinated DDoS against anti-piracy groups",
                "LulzSec: 50 days of chaos, multiple high-profile breaches",
                "Anonymous vs ISIS: Taking down propaganda accounts"
            ]
        )
        
        self.register_profile(hacktivist_profile)
    
    def register_profile(self, profile: AttackerProfile):
        """Register an attacker profile"""
        self.profiles[profile.profile_id] = profile
    
    def get_profile(self, profile_id: str) -> Optional[AttackerProfile]:
        """Get profile by ID"""
        return self.profiles.get(profile_id)
    
    def get_profile_by_type(self, attacker_type: str) -> Optional[AttackerProfile]:
        """Get profile by attacker type name"""
        for profile in self.profiles.values():
            if profile.attacker_type.lower() == attacker_type.lower():
                return profile
        return None
    
    def identify_attacker_type(self, behavioral_data: Dict) -> List[Dict]:
        """
        Identify likely attacker type based on observed behaviors
        
        Args:
            behavioral_data: Dict with observed characteristics
                {
                    'uses_automation': True,
                    'covers_tracks': False,
                    'skill_indicators': 'low',
                    'persistence': 'low',
                    'timing': 'random',
                    'tools_used': ['nmap', 'sqlmap']
                }
        
        Returns:
            List of possible attacker types with confidence scores
        """
        matches = []
        
        for profile in self.profiles.values():
            score = 0.0
            max_score = 0.0
            
            # Check automation
            if 'uses_automation' in behavioral_data:
                max_score += 1.0
                if behavioral_data['uses_automation'] == profile.characteristics.uses_automation:
                    score += 1.0
            
            # Check track covering
            if 'covers_tracks' in behavioral_data:
                max_score += 1.0
                if behavioral_data['covers_tracks'] == profile.attack_patterns.covers_tracks:
                    score += 1.0
            
            # Check persistence
            if 'persistence' in behavioral_data:
                max_score += 1.0
                persist_match = {
                    'low': Persistence.GIVES_UP_QUICKLY.value,
                    'medium': Persistence.PERSISTENT.value,
                    'high': Persistence.EXTREMELY_PERSISTENT.value
                }
                if persist_match.get(behavioral_data['persistence']) == profile.characteristics.persistence_level:
                    score += 1.0
            
            # Check tools
            if 'tools_used' in behavioral_data:
                max_score += 1.0
                tool_overlap = set(behavioral_data['tools_used']) & set(profile.attack_patterns.common_tools)
                if tool_overlap:
                    score += len(tool_overlap) / len(behavioral_data['tools_used'])
            
            confidence = (score / max_score) if max_score > 0 else 0.0
            
            if confidence > 0.3:  # Only include if >30% match
                matches.append({
                    'attacker_type': profile.attacker_type,
                    'confidence': confidence,
                    'characteristics': profile.characteristics,
                    'likely_next_actions': profile.behavioral_indicators.post_exploitation_behavior[:3]
                })
        
        matches.sort(key=lambda x: x['confidence'], reverse=True)
        return matches
    
    def export_to_json(self, filepath: str):
        """Export profiles to JSON"""
        data = {}
        for profile_id, profile in self.profiles.items():
            data[profile_id] = {
                "profile_id": profile.profile_id,
                "attacker_type": profile.attacker_type,
                "description": profile.description,
                "prevalence": profile.prevalence,
                "characteristics": asdict(profile.characteristics),
                "attack_patterns": asdict(profile.attack_patterns),
                "behavioral_indicators": asdict(profile.behavioral_indicators),
                "decision_making": asdict(profile.decision_making),
                "typical_organizations": profile.typical_organizations,
                "motivations": profile.motivations,
                "end_goals": profile.end_goals,
                "real_world_examples": profile.real_world_examples,
                "case_studies": profile.case_studies
            }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def get_statistics(self) -> Dict:
        """Get profile statistics"""
        stats = {
            "total_profiles": len(self.profiles),
            "profiles": {}
        }
        
        for profile in self.profiles.values():
            stats["profiles"][profile.profile_id] = {
                "attacker_type": profile.attacker_type,
                "skill_level": profile.characteristics.skill_level,
                "sophistication": profile.characteristics.sophistication,
                "success_rate": profile.attack_patterns.typical_success_rate,
                "prevalence": profile.prevalence
            }
        
        return stats


# ============================================
# USAGE & TESTING
# ============================================

if __name__ == "__main__":
    library = AttackerProfileLibrary()
    
    # Test profile retrieval
    print("🎯 Script Kiddie Profile")
    sk_profile = library.get_profile_by_type("Script Kiddie")
    print(f"Skill Level: {sk_profile.characteristics.skill_level}")
    print(f"Persistence: {sk_profile.characteristics.persistence_level}")
    print(f"Success Rate: {sk_profile.attack_patterns.typical_success_rate:.0%}")
    print(f"Common Tools: {', '.join(sk_profile.attack_patterns.common_tools[:3])}")
    
    # Test attacker identification
    print("\n📊 Attacker Type Identification:")
    behavioral_data = {
        'uses_automation': True,
        'covers_tracks': False,
        'persistence': 'low',
        'tools_used': ['nmap', 'Hydra', 'sqlmap']
    }
    
    matches = library.identify_attacker_type(behavioral_data)
    for match in matches[:2]:
        print(f"\n  {match['attacker_type']}")
        print(f"    Confidence: {match['confidence']:.0%}")
        print(f"    Likely Actions: {', '.join(match['likely_next_actions'][:2])}")
    
    # Export
    library.export_to_json("playbooks/profiles/attacker_profiles.json")
    print("\n✅ Profiles exported!")
    
    # Statistics
    stats = library.get_statistics()
    print(f"\n📊 Statistics:")
    for profile_id, profile_stats in stats["profiles"].items():
        print(f"  {profile_stats['attacker_type']}:")
        print(f"    Sophistication: {profile_stats['sophistication']}")
        print(f"    Success Rate: {profile_stats['success_rate']:.0%}")