"""
Attack Motivations & Targets System
Defines attacker goals, target priorities, and asset valuations
"""

from dataclasses import dataclass, asdict
from typing import Dict, List, Optional
from enum import Enum
import json


class AttackerMotivation(Enum):
    """Primary motivations for attacks"""
    FINANCIAL_GAIN = "Financial Gain"
    ESPIONAGE = "Espionage"
    HACKTIVISM = "Hacktivism"
    RANSOMWARE = "Ransomware/Extortion"
    SABOTAGE = "Sabotage/Destruction"
    TESTING = "Testing/Research"
    REVENGE = "Revenge/Grudge"


class AssetValue(Enum):
    """Value classification for assets"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


@dataclass
class AttackMotivationProfile:
    """Complete motivation profile for an attack type"""
    motivation_id: str
    attack_id: str
    attack_name: str
    
    # Primary motivations (ranked)
    primary_motivations: List[Dict[str, any]]  # [{"motivation": "Financial Gain", "percentage": 80}]
    
    # What attackers want to achieve
    end_goals: List[str]
    
    # How they monetize/benefit
    monetization_methods: List[str]
    
    # Typical attacker profiles
    typical_attackers: List[str]


@dataclass
class TargetPriority:
    """Priority ranking for attack targets"""
    target_name: str
    asset_type: str  # database, file, account, system, network
    value_classification: str
    
    # Why this target is valuable
    value_reasons: List[str]
    
    # Typical contents/data
    typical_contents: List[str]
    
    # Market value estimates
    estimated_breach_cost: int  # USD
    dark_web_value: Optional[int]  # USD per record
    
    # Characteristics that make it attractive
    attractiveness_factors: List[str]
    
    # Likelihood of being targeted
    targeting_probability: float  # 0.0 to 1.0


@dataclass
class AssetCharacteristics:
    """Characteristics that make assets attractive to attackers"""
    characteristic_name: str
    description: str
    increases_risk_by: float  # multiplier
    
    # Examples
    example_assets: List[str]


@dataclass
class MotivationTargetSet:
    """Complete set of motivations and targets for an attack"""
    set_id: str
    attack_id: str
    attack_name: str
    
    motivation_profile: AttackMotivationProfile
    target_priorities: List[TargetPriority]
    asset_characteristics: List[AssetCharacteristics]
    
    # Prediction logic
    primary_target_prediction: str  # Most likely target
    secondary_targets: List[str]
    target_selection_factors: Dict[str, float]


class MotivationTargetLibrary:
    """Manages all motivation and target data"""
    
    def __init__(self):
        self.motivation_sets: Dict[str, MotivationTargetSet] = {}
        self._load_default_motivations()
    
    def _load_default_motivations(self):
        """Load predefined motivations and targets"""
        
        # ============================================
        # BRUTE FORCE ATTACK MOTIVATIONS
        # ============================================
        
        brute_force_motivation = AttackMotivationProfile(
            motivation_id="MOT-001",
            attack_id="ATK-AUTH-001",
            attack_name="Brute Force Attack",
            
            primary_motivations=[
                {"motivation": AttackerMotivation.FINANCIAL_GAIN.value, "percentage": 70},
                {"motivation": AttackerMotivation.ESPIONAGE.value, "percentage": 15},
                {"motivation": AttackerMotivation.SABOTAGE.value, "percentage": 10},
                {"motivation": AttackerMotivation.TESTING.value, "percentage": 5}
            ],
            
            end_goals=[
                "Gain unauthorized access to user accounts",
                "Steal sensitive data (credentials, personal info, financial data)",
                "Install malware or backdoors",
                "Pivot to other systems (lateral movement)",
                "Steal intellectual property",
                "Compromise email accounts for phishing",
                "Take over social media accounts",
                "Access financial accounts"
            ],
            
            monetization_methods=[
                "Sell stolen credentials on dark web ($1-$50 per account)",
                "Sell access to compromised systems ($100-$10,000)",
                "Use accounts for fraud/theft",
                "Ransom stolen data back to victim",
                "Use email access for business email compromise (BEC)",
                "Sell personal data to data brokers",
                "Use for identity theft",
                "Deploy ransomware after gaining access"
            ],
            
            typical_attackers=[
                "Script kiddies (opportunistic)",
                "Organized cybercriminal groups",
                "State-sponsored actors (for espionage)",
                "Competitors (industrial espionage)",
                "Disgruntled insiders"
            ]
        )
        
        brute_force_targets = [
            TargetPriority(
                target_name="Admin/Root Accounts",
                asset_type="account",
                value_classification=AssetValue.CRITICAL.value,
                
                value_reasons=[
                    "Full system control",
                    "Can disable security measures",
                    "Access to all data",
                    "Can create backdoors",
                    "Difficult to detect malicious actions"
                ],
                
                typical_contents=[
                    "System configuration",
                    "All user data",
                    "Security settings",
                    "Database credentials",
                    "Encryption keys"
                ],
                
                estimated_breach_cost=500000,
                dark_web_value=1000,
                
                attractiveness_factors=[
                    "Highest privilege level",
                    "Single point of total compromise",
                    "Can disable logging/monitoring",
                    "Often has weak passwords",
                    "High resale value"
                ],
                
                targeting_probability=0.95
            ),
            
            TargetPriority(
                target_name="Database Admin Accounts",
                asset_type="account",
                value_classification=AssetValue.CRITICAL.value,
                
                value_reasons=[
                    "Direct database access",
                    "Can extract all data",
                    "Can modify/delete records",
                    "Bypass application-level security",
                    "Access to backups"
                ],
                
                typical_contents=[
                    "Customer data",
                    "Payment information",
                    "Personal identifiable information (PII)",
                    "Business intelligence",
                    "Trade secrets"
                ],
                
                estimated_breach_cost=2000000,
                dark_web_value=500,
                
                attractiveness_factors=[
                    "Direct data access",
                    "No application layer restrictions",
                    "Can export bulk data",
                    "High-value data",
                    "Often overlooked in monitoring"
                ],
                
                targeting_probability=0.90
            ),
            
            TargetPriority(
                target_name="Email Accounts (Executive/Admin)",
                asset_type="account",
                value_classification=AssetValue.HIGH.value,
                
                value_reasons=[
                    "Business email compromise (BEC)",
                    "Access to sensitive communications",
                    "Can authorize fraudulent transactions",
                    "Password reset for other accounts",
                    "Contacts for phishing"
                ],
                
                typical_contents=[
                    "Confidential emails",
                    "Financial information",
                    "Contract details",
                    "Strategic plans",
                    "Employee/customer data"
                ],
                
                estimated_breach_cost=150000,
                dark_web_value=100,
                
                attractiveness_factors=[
                    "High trust from recipients",
                    "Can initiate wire transfers",
                    "Access to business relationships",
                    "Source of intelligence",
                    "Useful for social engineering"
                ],
                
                targeting_probability=0.85
            ),
            
            TargetPriority(
                target_name="Financial/Payment Accounts",
                asset_type="account",
                value_classification=AssetValue.CRITICAL.value,
                
                value_reasons=[
                    "Direct financial theft",
                    "Credit card information",
                    "Bank account details",
                    "Payment processor access",
                    "Immediate monetization"
                ],
                
                typical_contents=[
                    "Credit card numbers",
                    "Bank account information",
                    "Transaction history",
                    "Customer payment data",
                    "Billing information"
                ],
                
                estimated_breach_cost=3000000,
                dark_web_value=50,
                
                attractiveness_factors=[
                    "Immediate cash value",
                    "Easy to monetize",
                    "High demand on dark web",
                    "Can be used for fraud",
                    "Difficult to trace"
                ],
                
                targeting_probability=0.92
            ),
            
            TargetPriority(
                target_name="Service/API Accounts",
                asset_type="account",
                value_classification=AssetValue.HIGH.value,
                
                value_reasons=[
                    "Automated access to systems",
                    "Often has elevated privileges",
                    "Rarely monitored",
                    "No MFA usually",
                    "Long-lived credentials"
                ],
                
                typical_contents=[
                    "API keys",
                    "Database connections",
                    "Third-party service access",
                    "Cloud resource control",
                    "Automated processes"
                ],
                
                estimated_breach_cost=400000,
                dark_web_value=200,
                
                attractiveness_factors=[
                    "Weak authentication (no MFA)",
                    "High privileges",
                    "Less monitoring",
                    "Long-term access",
                    "Gateway to other systems"
                ],
                
                targeting_probability=0.75
            ),
            
            TargetPriority(
                target_name="Regular User Accounts",
                asset_type="account",
                value_classification=AssetValue.MEDIUM.value,
                
                value_reasons=[
                    "Volume play (compromise many)",
                    "Stepping stone to privilege escalation",
                    "Personal data theft",
                    "Credential stuffing target",
                    "Social engineering source"
                ],
                
                typical_contents=[
                    "Personal information",
                    "Work files",
                    "Email access",
                    "Application data",
                    "Low-level system access"
                ],
                
                estimated_breach_cost=5000,
                dark_web_value=5,
                
                attractiveness_factors=[
                    "Easier to compromise (weaker passwords)",
                    "Large number of targets",
                    "Users less security-aware",
                    "Useful for phishing",
                    "Can escalate privileges"
                ],
                
                targeting_probability=0.60
            )
        ]
        
        brute_force_characteristics = [
            AssetCharacteristics(
                characteristic_name="Weak Password Policy",
                description="System allows simple passwords, no complexity requirements",
                increases_risk_by=3.0,
                example_assets=[
                    "Legacy systems",
                    "Old applications",
                    "IoT devices",
                    "Default accounts"
                ]
            ),
            
            AssetCharacteristics(
                characteristic_name="No Account Lockout",
                description="Unlimited login attempts allowed",
                increases_risk_by=5.0,
                example_assets=[
                    "APIs without rate limiting",
                    "Misconfigured applications",
                    "Custom authentication systems",
                    "Legacy infrastructure"
                ]
            ),
            
            AssetCharacteristics(
                characteristic_name="No MFA/2FA",
                description="Only password required for authentication",
                increases_risk_by=10.0,
                example_assets=[
                    "Many internal systems",
                    "Legacy applications",
                    "Small business systems",
                    "Consumer accounts"
                ]
            ),
            
            AssetCharacteristics(
                characteristic_name="Publicly Accessible",
                description="Authentication endpoint accessible from internet",
                increases_risk_by=2.0,
                example_assets=[
                    "Web applications",
                    "VPN gateways",
                    "Remote desktop services",
                    "Email servers"
                ]
            ),
            
            AssetCharacteristics(
                characteristic_name="High-Value Data",
                description="Contains sensitive, valuable, or regulated data",
                increases_risk_by=4.0,
                example_assets=[
                    "Customer databases",
                    "Financial systems",
                    "Healthcare records",
                    "Intellectual property repositories"
                ]
            )
        ]
        
        brute_force_set = MotivationTargetSet(
            set_id="MOTTARG-001",
            attack_id="ATK-AUTH-001",
            attack_name="Brute Force Attack",
            motivation_profile=brute_force_motivation,
            target_priorities=brute_force_targets,
            asset_characteristics=brute_force_characteristics,
            primary_target_prediction="Admin/Root Accounts",
            secondary_targets=[
                "Database Admin Accounts",
                "Financial/Payment Accounts",
                "Email Accounts (Executive/Admin)"
            ],
            target_selection_factors={
                "privilege_level": 0.35,
                "data_value": 0.30,
                "accessibility": 0.20,
                "detection_risk": 0.15
            }
        )
        
        self.register_motivation_set(brute_force_set)
        
        # ============================================
        # SQL INJECTION ATTACK MOTIVATIONS
        # ============================================
        
        sql_injection_motivation = AttackMotivationProfile(
            motivation_id="MOT-002",
            attack_id="ATK-INJ-001",
            attack_name="SQL Injection Attack",
            
            primary_motivations=[
                {"motivation": AttackerMotivation.FINANCIAL_GAIN.value, "percentage": 75},
                {"motivation": AttackerMotivation.ESPIONAGE.value, "percentage": 15},
                {"motivation": AttackerMotivation.HACKTIVISM.value, "percentage": 5},
                {"motivation": AttackerMotivation.TESTING.value, "percentage": 5}
            ],
            
            end_goals=[
                "Extract sensitive data from database",
                "Steal customer information (PII)",
                "Steal payment card data",
                "Steal login credentials",
                "Modify database records",
                "Delete/corrupt data (sabotage)",
                "Bypass authentication",
                "Gain administrative access",
                "Install backdoor via database",
                "Execute system commands"
            ],
            
            monetization_methods=[
                "Sell stolen data on dark web ($10-$500 per record depending on type)",
                "Ransom stolen data back to victim",
                "Use stolen credentials for account takeover",
                "Sell database dumps to competitors",
                "Credit card fraud",
                "Identity theft",
                "Blackmail with exposed sensitive data",
                "Use backdoor access for ransomware deployment"
            ],
            
            typical_attackers=[
                "Organized cybercriminal groups",
                "Data brokers",
                "Competitors (industrial espionage)",
                "Nation-state actors",
                "Hacktivists (for data leaks)"
            ]
        )
        
        sql_injection_targets = [
            TargetPriority(
                target_name="Customer Database",
                asset_type="database",
                value_classification=AssetValue.CRITICAL.value,
                
                value_reasons=[
                    "Large volume of PII",
                    "Email addresses for phishing",
                    "Names, addresses, phone numbers",
                    "Purchase history",
                    "High resale value"
                ],
                
                typical_contents=[
                    "Full names",
                    "Email addresses",
                    "Physical addresses",
                    "Phone numbers",
                    "Date of birth",
                    "Account information"
                ],
                
                estimated_breach_cost=5000000,
                dark_web_value=10,
                
                attractiveness_factors=[
                    "High record count",
                    "Complete profiles",
                    "Multiple use cases",
                    "Easy to monetize",
                    "Compliance penalties for breach"
                ],
                
                targeting_probability=0.95
            ),
            
            TargetPriority(
                target_name="Payment/Credit Card Database",
                asset_type="database",
                value_classification=AssetValue.CRITICAL.value,
                
                value_reasons=[
                    "Immediate financial value",
                    "Credit card numbers",
                    "CVV codes",
                    "Billing addresses",
                    "Highest dark web prices"
                ],
                
                typical_contents=[
                    "Credit card numbers",
                    "Expiration dates",
                    "CVV/CVC codes",
                    "Cardholder names",
                    "Billing addresses",
                    "Transaction history"
                ],
                
                estimated_breach_cost=10000000,
                dark_web_value=50,
                
                attractiveness_factors=[
                    "Direct financial value",
                    "Immediate monetization",
                    "High demand",
                    "Fresh cards most valuable",
                    "Can be used for fraud"
                ],
                
                targeting_probability=0.98
            ),
            
            TargetPriority(
                target_name="User Credentials Table",
                asset_type="database",
                value_classification=AssetValue.CRITICAL.value,
                
                value_reasons=[
                    "Login credentials for all users",
                    "Email/password combinations",
                    "Useful for credential stuffing",
                    "Account takeover potential",
                    "Access to user accounts"
                ],
                
                typical_contents=[
                    "Usernames",
                    "Email addresses",
                    "Password hashes (or plaintext if poorly secured)",
                    "Security questions",
                    "Account status",
                    "User roles/permissions"
                ],
                
                estimated_breach_cost=3000000,
                dark_web_value=5,
                
                attractiveness_factors=[
                    "Enables account takeover",
                    "Credential stuffing attacks",
                    "Many users reuse passwords",
                    "Gateway to other systems",
                    "Can escalate privileges"
                ],
                
                targeting_probability=0.92
            ),
            
            TargetPriority(
                target_name="Financial Records/Transactions",
                asset_type="database",
                value_classification=AssetValue.HIGH.value,
                
                value_reasons=[
                    "Revenue data",
                    "Transaction details",
                    "Bank account information",
                    "Financial intelligence",
                    "Competitive intelligence"
                ],
                
                typical_contents=[
                    "Transaction amounts",
                    "Payment methods",
                    "Account balances",
                    "Revenue reports",
                    "Financial projections"
                ],
                
                estimated_breach_cost=2000000,
                dark_web_value=100,
                
                attractiveness_factors=[
                    "Business intelligence value",
                    "Competitive advantage",
                    "Fraud potential",
                    "Blackmail material",
                    "Market manipulation"
                ],
                
                targeting_probability=0.80
            ),
            
            TargetPriority(
                target_name="Healthcare/Medical Records",
                asset_type="database",
                value_classification=AssetValue.CRITICAL.value,
                
                value_reasons=[
                    "Protected Health Information (PHI)",
                    "Complete identity profiles",
                    "Insurance information",
                    "Medical history",
                    "Highest value on dark web"
                ],
                
                typical_contents=[
                    "Patient names",
                    "Social Security numbers",
                    "Medical diagnoses",
                    "Prescriptions",
                    "Insurance details",
                    "Treatment history"
                ],
                
                estimated_breach_cost=7000000,
                dark_web_value=250,
                
                attractiveness_factors=[
                    "Most expensive on dark web",
                    "Complete identity data",
                    "Insurance fraud potential",
                    "HIPAA penalties",
                    "Long-term value"
                ],
                
                targeting_probability=0.88
            ),
            
            TargetPriority(
                target_name="Employee/HR Database",
                asset_type="database",
                value_classification=AssetValue.HIGH.value,
                
                value_reasons=[
                    "Complete employee records",
                    "SSNs and tax information",
                    "Salary data",
                    "Background checks",
                    "Internal intelligence"
                ],
                
                typical_contents=[
                    "Employee names",
                    "Social Security numbers",
                    "Addresses",
                    "Salary information",
                    "Performance reviews",
                    "Employment history"
                ],
                
                estimated_breach_cost=1500000,
                dark_web_value=30,
                
                attractiveness_factors=[
                    "Identity theft potential",
                    "Tax fraud",
                    "Social engineering info",
                    "Insider recruitment",
                    "Competitive intelligence"
                ],
                
                targeting_probability=0.70
            ),
            
            TargetPriority(
                target_name="Intellectual Property Database",
                asset_type="database",
                value_classification=AssetValue.CRITICAL.value,
                
                value_reasons=[
                    "Trade secrets",
                    "Research data",
                    "Product designs",
                    "Source code",
                    "Competitive advantage"
                ],
                
                typical_contents=[
                    "Patents",
                    "Research findings",
                    "Product specifications",
                    "Manufacturing processes",
                    "Business strategies",
                    "Source code"
                ],
                
                estimated_breach_cost=20000000,
                dark_web_value=None,
                
                attractiveness_factors=[
                    "Unique, irreplaceable",
                    "Competitive intelligence",
                    "Nation-state interest",
                    "Long-term value",
                    "Hard to detect theft"
                ],
                
                targeting_probability=0.65
            )
        ]
        
        sql_injection_characteristics = [
            AssetCharacteristics(
                characteristic_name="No Input Validation",
                description="Application doesn't sanitize user input",
                increases_risk_by=10.0,
                example_assets=[
                    "Legacy web applications",
                    "Custom-built systems",
                    "Poorly coded forms",
                    "Search functions"
                ]
            ),
            
            AssetCharacteristics(
                characteristic_name="Verbose Error Messages",
                description="Database errors exposed to users",
                increases_risk_by=3.0,
                example_assets=[
                    "Development/staging sites",
                    "Poorly configured applications",
                    "Debug mode enabled in production"
                ]
            ),
            
            AssetCharacteristics(
                characteristic_name="Direct Database Access",
                description="Application directly constructs SQL queries",
                increases_risk_by=8.0,
                example_assets=[
                    "Applications without ORM",
                    "Legacy code",
                    "Custom database layers"
                ]
            ),
            
            AssetCharacteristics(
                characteristic_name="Privileged Database User",
                description="Application uses high-privilege database account",
                increases_risk_by=5.0,
                example_assets=[
                    "Admin-level database connections",
                    "Root database access",
                    "SA/DBA accounts"
                ]
            )
        ]
        
        sql_injection_set = MotivationTargetSet(
            set_id="MOTTARG-002",
            attack_id="ATK-INJ-001",
            attack_name="SQL Injection Attack",
            motivation_profile=sql_injection_motivation,
            target_priorities=sql_injection_targets,
            asset_characteristics=sql_injection_characteristics,
            primary_target_prediction="Payment/Credit Card Database",
            secondary_targets=[
                "Customer Database",
                "User Credentials Table",
                "Healthcare/Medical Records"
            ],
            target_selection_factors={
                "data_value": 0.40,
                "record_count": 0.25,
                "accessibility": 0.20,
                "monetization_ease": 0.15
            }
        )
        
        self.register_motivation_set(sql_injection_set)
        
        # ============================================
        # RANSOMWARE ATTACK MOTIVATIONS
        # ============================================
        
        ransomware_motivation = AttackMotivationProfile(
            motivation_id="MOT-003",
            attack_id="ATK-MAL-001",
            attack_name="Ransomware Attack",
            
            primary_motivations=[
                {"motivation": AttackerMotivation.RANSOMWARE.value, "percentage": 90},
                {"motivation": AttackerMotivation.SABOTAGE.value, "percentage": 8},
                {"motivation": AttackerMotivation.TESTING.value, "percentage": 2}
            ],
            
            end_goals=[
                "Encrypt critical business data",
                "Demand ransom payment",
                "Exfiltrate data for double extortion",
                "Disrupt business operations",
                "Cause financial/reputational damage",
                "Destroy backups to force payment",
                "Maximize ransom amount"
            ],
            
            monetization_methods=[
                "Direct ransom payments ($50K - $50M+ in cryptocurrency)",
                "Double extortion (payment + no data leak threat)",
                "Triple extortion (DDoS + encryption + leak threat)",
                "Sell stolen data if ransom not paid",
                "Ransomware-as-a-Service (RaaS) revenue sharing"
            ],
            
            typical_attackers=[
                "Organized ransomware gangs (REvil, Conti, LockBit)",
                "RaaS affiliates",
                "Nation-state actors (destructive attacks)",
                "Financially motivated criminals"
            ]
        )
        
        ransomware_targets = [
            TargetPriority(
                target_name="Backup Systems",
                asset_type="system",
                value_classification=AssetValue.CRITICAL.value,
                
                value_reasons=[
                    "Eliminates recovery option",
                    "Forces ransom payment",
                    "Maximizes impact",
                    "Increases leverage",
                    "No alternative to paying"
                ],
                
                typical_contents=[
                    "System backups",
                    "Database backups",
                    "File backups",
                    "Snapshot copies",
                    "Disaster recovery data"
                ],
                
                estimated_breach_cost=15000000,
                dark_web_value=None,
                
                attractiveness_factors=[
                    "Eliminates recovery",
                    "Increases ransom amount",
                    "Shows sophistication",
                    "Maximizes victim desperation",
                    "Often poorly protected"
                ],
                
                targeting_probability=0.99
            ),
            
            TargetPriority(
                target_name="File Servers",
                asset_type="system",
                value_classification=AssetValue.CRITICAL.value,
                
                value_reasons=[
                    "High volume of business files",
                    "Shared network resources",
                    "Critical to operations",
                    "Wide impact",
                    "Difficult to recreate"
                ],
                
                typical_contents=[
                    "Business documents",
                    "Contracts",
                    "Financial records",
                    "Project files",
                    "Employee documents"
                ],
                
                estimated_breach_cost=8000000,
                dark_web_value=None,
                
                attractiveness_factors=[
                    "High file count",
                    "Business-critical",
                    "Shared across organization",
                    "Cannot function without",
                    "Ransomware spreads via shares"
                ],
                
                targeting_probability=0.95
            ),
            
            TargetPriority(
                target_name="Database Servers",
                asset_type="system",
                value_classification=AssetValue.CRITICAL.value,
                
                value_reasons=[
                    "Mission-critical data",
                    "Cannot operate without",
                    "Contains all business data",
                    "Double extortion potential",
                    "High ransom amounts"
                ],
                
                typical_contents=[
                    "Customer data",
                    "Transaction records",
                    "Financial data",
                    "Operational data",
                    "Historical records"
                ],
                
                estimated_breach_cost=20000000,
                dark_web_value=None,
                
                attractiveness_factors=[
                    "Most valuable data",
                    "Business-critical",
                    "Can steal + encrypt",
                    "Double extortion",
                    "Justifies highest ransom"
                ],
                
                targeting_probability=0.92
            ),
            
            TargetPriority(
                target_name="Domain Controllers",
                asset_type="system",
                value_classification=AssetValue.CRITICAL.value,
                
                value_reasons=[
                    "Controls entire network",
                    "Can propagate to all systems",
                    "Authentication system",
                    "Maximum impact",
                    "Single point of failure"
                ],
                
                typical_contents=[
                    "Active Directory database",
                    "User accounts",
                    "Group policies",
                    "Authentication services",
                    "Network configuration"
                ],
                
                estimated_breach_cost=25000000,
                dark_web_value=None,
                
                attractiveness_factors=[
                    "Control entire network",
                    "Propagate to all systems",
                    "Maximum disruption",
                    "Cannot recover easily",
                    "Highest ransom leverage"
                ],
                
                targeting_probability=0.88
            ),
            
            TargetPriority(
                target_name="Production Systems",
                asset_type="system",
                value_classification=AssetValue.HIGH.value,
                
                value_reasons=[
                    "Stops business operations",
                    "Revenue loss per hour",
                    "Customer impact",
                    "SLA breaches",
                    "Reputation damage"
                ],
                
                typical_contents=[
                    "Web servers",
                    "Application servers",
                    "E-commerce platforms",
                    "Manufacturing control systems",
                    "Customer-facing systems"
                ],
                
                estimated_breach_cost=12000000,
                dark_web_value=None,
                
                attractiveness_factors=[
                    "Immediate revenue loss",
                    "Customer impact",
                    "Public visibility",
                    "Pressure to pay quickly",
                    "Reputation damage"
                ],
                
                targeting_probability=0.85
            )
        ]
        
        ransomware_characteristics = [
            AssetCharacteristics(
                characteristic_name="No Offline Backups",
                description="All backups are online and accessible",
                increases_risk_by=10.0,
                example_assets=[
                    "Network-attached backup systems",
                    "Cloud-only backups",
                    "Continuous replication"
                ]
            ),
            
            AssetCharacteristics(
                characteristic_name="Network-Accessible Systems",
                description="Systems accessible via SMB/RDP across network",
                increases_risk_by=5.0,
                example_assets=[
                    "File shares",
                    "Remote desktop services",
                    "Network storage"
                ]
            ),
            
            AssetCharacteristics(
                characteristic_name="High Business Value",
                description="Critical to business operations, cannot function without",
                increases_risk_by=8.0,
                example_assets=[
                    "ERP systems",
                    "Core business applications",
                    "Production databases",
                    "Customer-facing systems"
                ]
            ),
            
            AssetCharacteristics(
                characteristic_name="Poor Segmentation",
                description="Flat network, no isolation between systems",
                increases_risk_by=6.0,
                example_assets=[
                    "Small business networks",
                    "Legacy infrastructure",
                    "Poorly designed networks"
                ]
            )
        ]
        
        ransomware_set = MotivationTargetSet(
            set_id="MOTTARG-003",
            attack_id="ATK-MAL-001",
            attack_name="Ransomware Attack",
            motivation_profile=ransomware_motivation,
            target_priorities=ransomware_targets,
            asset_characteristics=ransomware_characteristics,
            primary_target_prediction="Backup Systems",
            secondary_targets=[
                "Domain Controllers",
                "Database Servers",
                "File Servers"
            ],
            target_selection_factors={
                "business_impact": 0.40,
                "eliminates_recovery": 0.35,
                "ransom_leverage": 0.15,
                "accessibility": 0.10
            }
        )
        
        self.register_motivation_set(ransomware_set)
    
    def register_motivation_set(self, motivation_set: MotivationTargetSet):
        """Register a motivation/target set"""
        self.motivation_sets[motivation_set.set_id] = motivation_set
    
    def get_motivation_set(self, set_id: str) -> Optional[MotivationTargetSet]:
        """Get motivation set by ID"""
        return self.motivation_sets.get(set_id)
    
    def get_motivation_set_by_attack_id(self, attack_id: str) -> Optional[MotivationTargetSet]:
        """Get motivation set by attack taxonomy ID"""
        for mot_set in self.motivation_sets.values():
            if mot_set.attack_id == attack_id:
                return mot_set
        return None
    
    def predict_target(self, attack_id: str, available_assets: List[str]) -> Dict:
        """
        Predict which target attacker will go after
        Based on asset characteristics and priorities
        """
        motivation_set = self.get_motivation_set_by_attack_id(attack_id)
        if not motivation_set:
            return {"error": "No motivation set found"}
        
        predictions = []
        for target in motivation_set.target_priorities:
            if target.target_name in available_assets or not available_assets:
                predictions.append({
                    "target": target.target_name,
                    "probability": target.targeting_probability,
                    "value": target.value_classification,
                    "estimated_cost": target.estimated_breach_cost,
                    "reasons": target.value_reasons[:3]
                })
        
        predictions.sort(key=lambda x: x['probability'], reverse=True)
        
        return {
            "primary_target": predictions[0] if predictions else None,
            "all_predictions": predictions,
            "attacker_motivation": motivation_set.motivation_profile.primary_motivations[0],
            "monetization": motivation_set.motivation_profile.monetization_methods[:3]
        }
    
    def export_to_json(self, filepath: str):
        """Export motivations to JSON"""
        data = {}
        for set_id, mot_set in self.motivation_sets.items():
            data[set_id] = {
                "set_id": mot_set.set_id,
                "attack_id": mot_set.attack_id,
                "attack_name": mot_set.attack_name,
                "motivation_profile": asdict(mot_set.motivation_profile),
                "target_priorities": [asdict(t) for t in mot_set.target_priorities],
                "asset_characteristics": [asdict(a) for a in mot_set.asset_characteristics],
                "primary_target_prediction": mot_set.primary_target_prediction,
                "secondary_targets": mot_set.secondary_targets,
                "target_selection_factors": mot_set.target_selection_factors
            }
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def get_statistics(self) -> Dict:
        """Get motivation statistics"""
        stats = {
            "total_sets": len(self.motivation_sets),
            "sets": {}
        }
        
        for mot_set in self.motivation_sets.values():
            stats["sets"][mot_set.set_id] = {
                "attack_name": mot_set.attack_name,
                "primary_motivation": mot_set.motivation_profile.primary_motivations[0],
                "target_count": len(mot_set.target_priorities),
                "primary_target": mot_set.primary_target_prediction,
                "avg_breach_cost": sum(t.estimated_breach_cost for t in mot_set.target_priorities) / len(mot_set.target_priorities)
            }
        
        return stats


# ============================================
# USAGE & TESTING
# ============================================

if __name__ == "__main__":
    library = MotivationTargetLibrary()
    
    # Test brute force motivations
    print("🎯 Brute Force Attack Motivations & Targets")
    bf_mots = library.get_motivation_set_by_attack_id("ATK-AUTH-001")
    print(f"Primary Motivation: {bf_mots.motivation_profile.primary_motivations[0]}")
    print(f"Target Count: {len(bf_mots.target_priorities)}")
    print(f"Primary Target: {bf_mots.primary_target_prediction}")
    
    # Test target prediction
    print("\n📊 Target Prediction:")
    prediction = library.predict_target("ATK-AUTH-001", [])
    if prediction.get("primary_target"):
        print(f"  Most Likely Target: {prediction['primary_target']['target']}")
        print(f"  Probability: {prediction['primary_target']['probability']:.0%}")
        print(f"  Estimated Breach Cost: ${prediction['primary_target']['estimated_cost']:,}")
    
    # Export
    library.export_to_json("playbooks/motivations/motivations_targets.json")
    print("\n✅ Motivations exported!")
    
    # Statistics
    stats = library.get_statistics()
    print(f"\n📊 Statistics:")
    for set_id, set_stats in stats["sets"].items():
        print(f"  {set_stats['attack_name']}:")
        print(f"    Primary Target: {set_stats['primary_target']}")
        print(f"    Avg Breach Cost: ${set_stats['avg_breach_cost']:,.0f}")