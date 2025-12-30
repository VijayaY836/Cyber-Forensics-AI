"""
Playbook Manager - Master Orchestrator
Integrates all playbook modules to provide comprehensive attack analysis and prediction
"""

from typing import Dict, List, Optional
from datetime import datetime, timedelta
import pandas as pd

from .playbook_taxonomy import AttackTaxonomy
from .playbook_sequences import AttackSequenceLibrary
from .playbook_indicators import BehavioralIndicatorLibrary
from .playbook_motivations import MotivationTargetLibrary
from .playbook_timing import TimingPatternLibrary
from .playbook_profiles import AttackerProfileLibrary
from .playbook_countermeasures import CountermeasureLibrary


class PlaybookManager:
    """
    Central orchestrator for all playbook functionality
    Provides high-level interface for attack prediction and analysis
    """
    
    def __init__(self):
        # Initialize all playbook modules
        self.taxonomy = AttackTaxonomy()
        self.sequences = AttackSequenceLibrary()
        self.indicators = BehavioralIndicatorLibrary()
        self.motivations = MotivationTargetLibrary()
        self.timing = TimingPatternLibrary()
        self.profiles = AttackerProfileLibrary()
        self.countermeasures = CountermeasureLibrary()
    
    def identify_attack(self, log_patterns: Dict) -> List[Dict]:
        """
        Identify attack type from observed log patterns
    
        Args:
            log_patterns: Dictionary with observed patterns
                {
                    'failed_logins': 47,
                    'sql_keywords': 3,
                    'sql_errors': 5,
                    'mass_file_modifications': 200,
                    'ransom_note_files': 2,
                    'encrypted_extensions': 15,
                    'shadow_copy_deletion': 1,
                    'unusual_ip': True,
                    'off_hours': True
                }
    
        Returns:
            List of potential attacks with confidence scores
        """
        matches = []
    
        # Check for brute force patterns
        if log_patterns.get('failed_logins', 0) > 10:
            attack = self.taxonomy.get_attack("ATK-AUTH-001")
            confidence = min(0.95, 0.5 + (log_patterns['failed_logins'] / 100))
            matches.append({
                'attack': attack,
                'attack_id': attack.attack_id,
                'attack_name': attack.attack_name,
                'confidence': confidence,
                'severity': attack.base_severity,
                'reason': f"{log_patterns['failed_logins']} failed login attempts detected"
            })
    
        # Check for SQL injection patterns - MORE SPECIFIC NOW
        sql_keywords = log_patterns.get('sql_keywords', 0)
        sql_errors = log_patterns.get('sql_errors', 0)
    
        # Only trigger if we have ACTUAL SQL injection indicators
        if sql_keywords > 5 or (sql_keywords > 0 and sql_errors > 3):
            attack = self.taxonomy.get_attack("ATK-INJ-001")
            confidence = min(0.95, 0.5 + ((sql_keywords + sql_errors) / 20))
            matches.append({
                'attack': attack,
                'attack_id': attack.attack_id,
                'attack_name': attack.attack_name,
                'confidence': confidence,
                'severity': attack.base_severity,
                'reason': f"{sql_keywords} SQL keywords detected, {sql_errors} database errors"
            })
    
        # Check for ransomware patterns - PRIORITY CHECK
        ransom_indicators = (
            log_patterns.get('ransom_note_files', 0) +
            log_patterns.get('encrypted_extensions', 0) +
            log_patterns.get('shadow_copy_deletion', 0)
        )
    
        mass_modifications = log_patterns.get('mass_file_modifications', 0)
    
        # Ransomware has HIGH PRIORITY if specific indicators are present
        if ransom_indicators > 0 or mass_modifications > 100:
            attack = self.taxonomy.get_attack("ATK-MAL-001")
        
            # High confidence if we see ransom-specific indicators
            if ransom_indicators > 0:
                confidence = 0.95
                reason = f"Ransomware indicators: {ransom_indicators} ransom files/encrypted extensions/shadow deletions, {mass_modifications} file modifications"
            else:
                confidence = 0.80
                reason = f"{mass_modifications} files modified rapidly"
        
            matches.append({
                'attack': attack,
                'attack_id': attack.attack_id,
                'attack_name': attack.attack_name,
                'confidence': confidence,
                'severity': attack.base_severity,
                'reason': reason
            })
    
        # Sort by confidence
        matches.sort(key=lambda x: x['confidence'], reverse=True)
        return matches
    
    def predict_next_stage(
        self,
        attack_id: str,
        current_stage: int,
        current_time: Optional[datetime] = None,
        attacker_type: str = "Cybercriminal"
    ) -> Dict:
        """
        Predict what will happen next in the attack
        
        Args:
            attack_id: Attack taxonomy ID
            current_stage: Current stage number
            current_time: Current timestamp (defaults to now)
            attacker_type: Type of attacker
        
        Returns:
            Comprehensive prediction with timing, targets, and countermeasures
        """
        if current_time is None:
            current_time = datetime.now()
        
        # Get attack info
        attack = self.taxonomy.get_attack(attack_id)
        if not attack:
            return {"error": "Attack not found"}
        
        # Get sequence prediction
        sequence = self.sequences.get_sequence_by_attack_id(attack_id)
        next_stage_pred = self.sequences.predict_next_stage(sequence.sequence_id, current_stage)
        
        # Get timing prediction
        timing_pred = self.timing.predict_next_stage_timing(
            attack_id, 
            current_stage, 
            current_time,
            attacker_type
        )
        
        # Get target prediction
        motivation_set = self.motivations.get_motivation_set_by_attack_id(attack_id)
        target_pred = self.motivations.predict_target(attack_id, [])
        
        # Get countermeasures
        cm_recommendations = self.countermeasures.recommend_countermeasures(
            attack_id,
            current_stage,
            urgency="CRITICAL"
        )
        
        # Time to point of no return
        ponr = self.timing.calculate_time_to_point_of_no_return(
            attack_id,
            current_stage,
            current_time
        )
        
        return {
            "attack_name": attack.attack_name,
            "attack_severity": attack.base_severity,
            "current_stage": current_stage,
            "attacker_type": attacker_type,
            
            "next_stage": {
                "stage_number": next_stage_pred['next_stage'].stage_number if next_stage_pred else None,
                "stage_name": next_stage_pred['next_stage'].stage_name if next_stage_pred else None,
                "probability": f"{next_stage_pred['probability']:.0%}" if next_stage_pred else "N/A",
                "severity": next_stage_pred['severity'] if next_stage_pred else None
            },
            
            "timing": {
                "predicted_time_window": timing_pred.get('predicted_time_window'),
                "minutes_until_next": timing_pred.get('minutes_until_next'),
                "detection_window_remaining": timing_pred.get('detection_window_remaining', 0)
            },
            
            "likely_targets": {
                "primary": target_pred['primary_target']['target'] if target_pred.get('primary_target') else None,
                "probability": f"{target_pred['primary_target']['probability']:.0%}" if target_pred.get('primary_target') else None,
                "estimated_damage": f"${target_pred['primary_target']['estimated_cost']:,}" if target_pred.get('primary_target') else None
            },
            
            "point_of_no_return": ponr,
            
            "recommended_actions": cm_recommendations.get('immediate_actions', []),
            
            "confidence": next_stage_pred.get('confidence', 0.0) if next_stage_pred else 0.0
        }
    
    def get_full_attack_analysis(self, attack_id: str, current_stage: int = 1) -> Dict:
        """
        Get comprehensive analysis of an attack
        
        Args:
            attack_id: Attack taxonomy ID
            current_stage: Current stage of attack
        
        Returns:
            Complete analysis with all playbook information
        """
        attack = self.taxonomy.get_attack(attack_id)
        if not attack:
            return {"error": "Attack not found"}
        
        sequence = self.sequences.get_sequence_by_attack_id(attack_id)
        indicators = self.indicators.get_indicator_set_by_attack_id(attack_id)
        motivations = self.motivations.get_motivation_set_by_attack_id(attack_id)
        timing = self.timing.get_timing_set_by_attack_id(attack_id)
        countermeasures = self.countermeasures.get_countermeasure_set_by_attack_id(attack_id)
        
        return {
            "attack_overview": {
                "name": attack.attack_name,
                "category": attack.category,
                "severity": attack.base_severity,
                "description": attack.description,
                "typical_attacker": attack.typical_attacker,
                "detection_difficulty": attack.detection_difficulty,
                "prevalence": attack.prevalence
            },
            
            "attack_stages": {
                "total_stages": sequence.total_stages if sequence else 0,
                "current_stage": current_stage,
                "stages": [
                    {
                        "number": stage.stage_number,
                        "name": stage.stage_name,
                        "description": stage.description,
                        "duration": f"{stage.typical_duration_minutes} minutes",
                        "success_rate": f"{stage.success_rate:.0%}"
                    }
                    for stage in sequence.stages
                ] if sequence else []
            },
            
            "behavioral_indicators": {
                "quantitative_count": len(indicators.quantitative_indicators) if indicators else 0,
                "qualitative_count": len(indicators.qualitative_indicators) if indicators else 0,
                "temporal_count": len(indicators.temporal_indicators) if indicators else 0,
                "key_signatures": attack.log_signatures[:5]
            },
            
            "attacker_motivations": {
                "primary_motivation": motivations.motivation_profile.primary_motivations[0] if motivations else None,
                "end_goals": motivations.motivation_profile.end_goals[:3] if motivations else [],
                "monetization": motivations.motivation_profile.monetization_methods[:2] if motivations else []
            },
            
            "target_priorities": {
                "primary_target": motivations.primary_target_prediction if motivations else None,
                "secondary_targets": motivations.secondary_targets if motivations else []
            },
            
            "timing_analysis": {
                "typical_duration": f"{timing.attack_timeline.typical_total_duration_minutes / 60:.1f} hours" if timing else None,
                "attack_speed": timing.attack_timeline.attack_speed_category if timing else None,
                "point_of_no_return": f"Stage {timing.attack_timeline.point_of_no_return_stage}" if timing else None
            },
            
            "defensive_strategy": {
                "total_countermeasures": len(countermeasures.countermeasures) if countermeasures else 0,
                "overall_effectiveness": f"{countermeasures.defensive_strategy.overall_effectiveness:.0%}" if countermeasures else None,
                "immediate_actions": countermeasures.defensive_strategy.immediate_actions if countermeasures else []
            },
            
            "impact_assessment": {
                "confidentiality": attack.confidentiality_impact,
                "integrity": attack.integrity_impact,
                "availability": attack.availability_impact
            }
        }
    
    def analyze_behavioral_data(self, behavioral_data: Dict) -> Dict:
        """
        Analyze behavioral data to identify attacker type and likely attack
        
        Args:
            behavioral_data: Observed behaviors
                {
                    'uses_automation': True,
                    'covers_tracks': False,
                    'persistence': 'low',
                    'tools_used': ['nmap', 'sqlmap']
                }
        
        Returns:
            Analysis with attacker identification and predictions
        """
        try:
            # Identify attacker type
            attacker_matches = self.profiles.identify_attacker_type(behavioral_data)
            
            if not attacker_matches:
                # Return default analysis if no matches
                return {
                    "error": "Could not identify attacker type with sufficient confidence",
                    "identified_attacker": {
                        "type": "Unknown",
                        "confidence": "0%",
                        "skill_level": "Unknown",
                        "sophistication": "Unknown",
                        "persistence": "Unknown"
                    },
                    "likely_attacks": ["Unknown"],
                    "expected_behaviors": {
                        "prefers_stealth": False,
                        "covers_tracks": False,
                        "typical_duration": "Unknown",
                        "success_rate": "0%"
                    },
                    "likely_next_actions": ["Insufficient data for prediction"],
                    "decision_making": {
                        "when_proceeds": ["Unknown"],
                        "when_aborts": ["Unknown"],
                        "adapts_to_defenses": False
                    },
                    "motivations": ["Unknown"],
                    "end_goals": ["Unknown"]
                }
            
            best_match = attacker_matches[0]
            attacker_profile = self.profiles.get_profile_by_type(best_match['attacker_type'])
            
            if not attacker_profile:
                return {"error": "Profile data unavailable"}
            
            return {
                "identified_attacker": {
                    "type": best_match['attacker_type'],
                    "confidence": f"{best_match['confidence']:.0%}",
                    "skill_level": attacker_profile.characteristics.skill_level,
                    "sophistication": attacker_profile.characteristics.sophistication,
                    "persistence": attacker_profile.characteristics.persistence_level
                },
                
                "likely_attacks": attacker_profile.attack_patterns.preferred_attack_types,
                
                "expected_behaviors": {
                    "prefers_stealth": attacker_profile.attack_patterns.prefers_stealth,
                    "covers_tracks": attacker_profile.attack_patterns.covers_tracks,
                    "typical_duration": attacker_profile.attack_patterns.average_attack_duration,
                    "success_rate": f"{attacker_profile.attack_patterns.typical_success_rate:.0%}"
                },
                
                "likely_next_actions": best_match.get('likely_next_actions', []),
                
                "decision_making": {
                    "when_proceeds": attacker_profile.decision_making.when_to_proceed[:3],
                    "when_aborts": attacker_profile.decision_making.when_to_abort[:3],
                    "adapts_to_defenses": attacker_profile.decision_making.adapts_to_defenses
                },
                
                "motivations": attacker_profile.motivations[:3],
                "end_goals": attacker_profile.end_goals[:3]
            }
        
        except Exception as e:
            # Graceful fallback
            return {
                "error": f"Analysis error: {str(e)}",
                "identified_attacker": {
                    "type": "Unknown",
                    "confidence": "0%",
                    "skill_level": "Unknown",
                    "sophistication": "Unknown",
                    "persistence": "Unknown"
                },
                "likely_attacks": ["Analysis unavailable"],
                "expected_behaviors": {
                    "prefers_stealth": False,
                    "covers_tracks": False,
                    "typical_duration": "Unknown",
                    "success_rate": "0%"
                },
                "likely_next_actions": ["Insufficient data"],
                "decision_making": {
                    "when_proceeds": ["Unknown"],
                    "when_aborts": ["Unknown"],
                    "adapts_to_defenses": False
                },
                "motivations": ["Unknown"],
                "end_goals": ["Unknown"]
            }
    
    def get_statistics(self) -> Dict:
        """Get statistics from all playbook modules"""
        return {
            "taxonomy": self.taxonomy.get_statistics(),
            "sequences": self.sequences.get_statistics(),
            "indicators": self.indicators.get_statistics(),
            "motivations": self.motivations.get_statistics(),
            "timing": self.timing.get_statistics(),
            "profiles": self.profiles.get_statistics(),
            "countermeasures": self.countermeasures.get_statistics()
        }
    
    def export_all_playbooks(self, base_path: str = "playbooks"):
        """Export all playbooks to JSON files"""
        self.taxonomy.export_to_json(f"{base_path}/taxonomy/attack_taxonomy.json")
        self.sequences.export_to_json(f"{base_path}/sequences/attack_sequences.json")
        self.indicators.export_to_json(f"{base_path}/indicators/behavioral_indicators.json")
        self.motivations.export_to_json(f"{base_path}/motivations/motivations_targets.json")
        self.timing.export_to_json(f"{base_path}/timing/timing_patterns.json")
        self.profiles.export_to_json(f"{base_path}/profiles/attacker_profiles.json")
        self.countermeasures.export_to_json(f"{base_path}/countermeasures/countermeasures.json")


# ============================================
# USAGE & TESTING
# ============================================

if __name__ == "__main__":
    print("🚀 Initializing Playbook Manager...")
    manager = PlaybookManager()
    print("✅ All playbook modules loaded!\n")
    
    # Test 1: Attack Identification
    print("=" * 60)
    print("TEST 1: ATTACK IDENTIFICATION")
    print("=" * 60)
    
    log_patterns = {
        'failed_logins': 47,
        'sql_keywords': 0,
        'unusual_ip': True,
        'off_hours': True
    }
    
    attacks = manager.identify_attack(log_patterns)
    print(f"\n🎯 Detected Attacks:")
    for attack in attacks:
        print(f"  • {attack['attack_name']}")
        print(f"    Confidence: {attack['confidence']:.0%}")
        print(f"    Severity: {attack['severity']}")
        print(f"    Reason: {attack['reason']}")
    
    # Test 2: Next Stage Prediction
    print("\n" + "=" * 60)
    print("TEST 2: NEXT STAGE PREDICTION")
    print("=" * 60)
    
    if attacks:
        attack_id = attacks[0]['attack_id']
        prediction = manager.predict_next_stage(attack_id, 2)
        
        print(f"\n📊 Prediction for {prediction['attack_name']}:")
        print(f"  Current Stage: {prediction['current_stage']}")
        print(f"  Next Stage: {prediction['next_stage']['stage_name']}")
        print(f"  Probability: {prediction['next_stage']['probability']}")
        print(f"  Time Until Next: {prediction['timing']['minutes_until_next']['typical']} minutes")
        print(f"  Primary Target: {prediction['likely_targets']['primary']}")
        print(f"  Estimated Damage: {prediction['likely_targets']['estimated_damage']}")
        
        print(f"\n⚠️ Point of No Return:")
        ponr = prediction['point_of_no_return']
        print(f"  Status: {ponr['status']}")
        print(f"  Can Stop: {ponr['can_still_stop']}")
        print(f"  Time Remaining: {ponr.get('minutes_remaining', 'N/A')} minutes")
        
        print(f"\n🛡️ Recommended Actions:")
        for action in prediction['recommended_actions'][:2]:
            print(f"  • {action['action']}")
            print(f"    Effectiveness: {action['effectiveness']}")
            print(f"    Time: {action['time']}")
    
    # Test 3: Full Attack Analysis
    print("\n" + "=" * 60)
    print("TEST 3: COMPREHENSIVE ATTACK ANALYSIS")
    print("=" * 60)
    
    analysis = manager.get_full_attack_analysis("ATK-AUTH-001", current_stage=2)
    print(f"\n📋 Analysis for {analysis['attack_overview']['name']}:")
    print(f"  Category: {analysis['attack_overview']['category']}")
    print(f"  Severity: {analysis['attack_overview']['severity']}")
    print(f"  Detection Difficulty: {analysis['attack_overview']['detection_difficulty']}")
    print(f"\n  Total Stages: {analysis['attack_stages']['total_stages']}")
    print(f"  Current Stage: {analysis['attack_stages']['current_stage']}")
    print(f"\n  Primary Motivation: {analysis['attacker_motivations']['primary_motivation']}")
    print(f"  Primary Target: {analysis['target_priorities']['primary_target']}")
    print(f"\n  Typical Duration: {analysis['timing_analysis']['typical_duration']}")
    print(f"  Attack Speed: {analysis['timing_analysis']['attack_speed']}")
    print(f"\n  Available Countermeasures: {analysis['defensive_strategy']['total_countermeasures']}")
    print(f"  Defense Effectiveness: {analysis['defensive_strategy']['overall_effectiveness']}")
    
    # Test 4: Attacker Profiling
    print("\n" + "=" * 60)
    print("TEST 4: ATTACKER PROFILING")
    print("=" * 60)
    
    behavioral_data = {
        'uses_automation': True,
        'covers_tracks': False,
        'persistence': 'low',
        'tools_used': ['nmap', 'Hydra']
    }
    
    profile_analysis = manager.analyze_behavioral_data(behavioral_data)
    print(f"\n👤 Identified Attacker:")
    print(f"  Type: {profile_analysis['identified_attacker']['type']}")
    print(f"  Confidence: {profile_analysis['identified_attacker']['confidence']}")
    print(f"  Skill Level: {profile_analysis['identified_attacker']['skill_level']}")
    print(f"  Sophistication: {profile_analysis['identified_attacker']['sophistication']}")
    print(f"\n  Likely Attacks: {', '.join(profile_analysis['likely_attacks'][:3])}")
    print(f"  Success Rate: {profile_analysis['expected_behaviors']['success_rate']}")
    print(f"  Adapts to Defenses: {profile_analysis['decision_making']['adapts_to_defenses']}")
    
    # Test 5: Statistics
    print("\n" + "=" * 60)
    print("TEST 5: PLAYBOOK STATISTICS")
    print("=" * 60)
    
    stats = manager.get_statistics()
    print(f"\n📊 Playbook Library Statistics:")
    print(f"  Attack Types: {stats['taxonomy']['total_attacks']}")
    print(f"  Attack Sequences: {stats['sequences']['total_sequences']}")
    print(f"  Indicator Sets: {stats['indicators']['total_indicator_sets']}")
    print(f"  Motivation Profiles: {stats['motivations']['total_sets']}")
    print(f"  Timing Patterns: {stats['timing']['total_timing_sets']}")
    print(f"  Attacker Profiles: {stats['profiles']['total_profiles']}")
    print(f"  Countermeasure Sets: {stats['countermeasures']['total_sets']}")
    
    # Export all playbooks
    print("\n" + "=" * 60)
    print("EXPORTING ALL PLAYBOOKS")
    print("=" * 60)
    
    manager.export_all_playbooks()
    print("\n✅ All playbooks exported successfully!")
    
    print("\n" + "=" * 60)
    print("🎉 PLAYBOOK MANAGER TEST COMPLETE!")
    print("=" * 60)