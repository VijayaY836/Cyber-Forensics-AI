"""
Forensic Report Generator Module
Generates comprehensive, explainable forensic analysis reports
"""

import pandas as pd
from datetime import datetime
import numpy as np

class ForensicReportGenerator:
    """
    Generates comprehensive forensic investigation reports
    Includes executive summary, technical analysis, and recommendations
    """
    
    def __init__(self):
        """Initialize the report generator"""
        self.report_metadata = {
            'generated_at': datetime.now(),
            'tool_name': 'AI-Based Log Investigation Framework',
            'version': '1.0.0',
            'analyst': 'Automated ML System'
        }
    
    def generate_report(self, logs_df, anomaly_df=None, correlation_results=None, 
                       timeline_results=None, log_stats=None, prediction_results=None):
        """
        Generate comprehensive forensic report
        
        Args:
            logs_df: Original logs DataFrame
            anomaly_df: Anomaly detection results
            correlation_results: Event correlation results
            timeline_results: Timeline analysis results
            log_stats: Log parsing statistics
            prediction_results: Attack prediction results 
            
        Returns:
            str: Complete report in Markdown format
        """
        report = []
        
        # Header
        report.append(self._generate_header())
        
        # Executive Summary
        report.append(self._generate_executive_summary(
            logs_df, anomaly_df, correlation_results, timeline_results
        ))
        
        # Incident Overview
        report.append(self._generate_incident_overview(
            logs_df, anomaly_df, timeline_results
        ))
        
        # Technical Analysis
        report.append(self._generate_technical_analysis(
            anomaly_df, correlation_results, timeline_results
        ))

        # Attack Prediction Analysis
        if prediction_results:
            report.append(self._generate_prediction_section(prediction_results))
        
        # Attack Timeline
        if timeline_results:
            report.append(self._generate_timeline_section(timeline_results))
        
        # Evidence Summary
        report.append(self._generate_evidence_summary(
            anomaly_df, correlation_results
        ))
        
        # Indicators of Compromise
        report.append(self._generate_ioc_section(anomaly_df))
        
        # Confidence Assessment
        report.append(self._generate_confidence_assessment(
            anomaly_df, correlation_results
        ))
        
        # Recommendations
        report.append(self._generate_recommendations(
            anomaly_df, correlation_results, timeline_results
        ))
        
        # Appendix
        report.append(self._generate_appendix(log_stats))
        
        # Footer
        report.append(self._generate_footer())
        
        return '\n\n'.join(report)
    
    def _generate_header(self):
        """Generate report header"""
        header = f"""# 🔍 CYBER FORENSIC INVESTIGATION REPORT

**Generated:** {self.report_metadata['generated_at'].strftime('%Y-%m-%d %H:%M:%S')}  
**Tool:** {self.report_metadata['tool_name']} v{self.report_metadata['version']}  
**Analysis Type:** Automated Machine Learning-Based Investigation  
**Classification:** CONFIDENTIAL - FOR AUTHORIZED PERSONNEL ONLY

---
"""
        return header
    
    def _generate_executive_summary(self, logs_df, anomaly_df, correlation_results, timeline_results):
        """Generate executive summary"""
        summary = "## 📊 EXECUTIVE SUMMARY\n\n"
        
        # Determine overall severity
        if anomaly_df is not None:
            critical_count = (anomaly_df['severity_level'] == 'CRITICAL').sum()
            high_count = (anomaly_df['severity_level'] == 'HIGH').sum()
            
            if critical_count > 0:
                overall_severity = "**CRITICAL**"
                summary += "### ⚠️ CRITICAL SECURITY INCIDENT DETECTED\n\n"
            elif high_count > 5:
                overall_severity = "**HIGH**"
                summary += "### ⚠️ HIGH SEVERITY SECURITY EVENT DETECTED\n\n"
            else:
                overall_severity = "**MEDIUM**"
                summary += "### ℹ️ SECURITY ANOMALIES DETECTED\n\n"
        else:
            overall_severity = "**UNKNOWN**"
            summary += "### ℹ️ LOG ANALYSIS COMPLETED\n\n"
        
        summary += f"**Overall Severity:** {overall_severity}\n\n"
        
        # Key findings
        summary += "**Key Findings:**\n\n"
        
        if anomaly_df is not None:
            anomaly_count = (anomaly_df['is_anomaly'] == 1).sum()
            anomaly_pct = (anomaly_count / len(anomaly_df)) * 100
            
            summary += f"- **{anomaly_count}** anomalous events detected ({anomaly_pct:.1f}% of total activity)\n"
            
            if critical_count > 0:
                summary += f"- **{critical_count}** events classified as CRITICAL severity\n"
            
            if high_count > 0:
                summary += f"- **{high_count}** events classified as HIGH severity\n"
        
        if correlation_results and correlation_results['attack_chains_detected'] > 0:
            chains = correlation_results['attack_chains_detected']
            summary += f"- **{chains}** multi-stage attack chain(s) identified\n"
            
            # Count attackers
            unique_attackers = correlation_results['unique_attackers']
            summary += f"- **{unique_attackers}** unique attacker IP address(es) identified\n"
        
        if timeline_results:
            phases = timeline_results['stats']['phases_observed']
            summary += f"- Attack progressed through **{phases}** kill chain phases\n"
            
            duration = timeline_results['stats']['time_span']
            duration_hours = duration.total_seconds() / 3600
            if duration_hours >= 1:
                summary += f"- Attack duration: **{duration_hours:.1f} hours**\n"
            else:
                summary += f"- Attack duration: **{duration.total_seconds()/60:.0f} minutes**\n"
        
        # Recommendation
        summary += "\n**Immediate Actions Required:**\n\n"
        
        if anomaly_df is not None and critical_count > 0:
            summary += "1. 🚨 Isolate affected systems immediately\n"
            summary += "2. 🔒 Reset compromised credentials\n"
            summary += "3. 🔍 Conduct full incident response investigation\n"
            summary += "4. 📞 Notify security operations center (SOC)\n"
        elif anomaly_df is not None and high_count > 0:
            summary += "1. 🔍 Review flagged events with security team\n"
            summary += "2. 🔒 Verify user account integrity\n"
            summary += "3. 📊 Monitor for continued suspicious activity\n"
        else:
            summary += "1. 📊 Continue monitoring for anomalous patterns\n"
            summary += "2. ✅ Review and validate detected anomalies\n"
        
        return summary
    
    def _generate_incident_overview(self, logs_df, anomaly_df, timeline_results):
        """Generate incident overview section"""
        section = "## 📋 INCIDENT OVERVIEW\n\n"
        
        section += "### Timeline\n\n"
        
        if timeline_results:
            stats = timeline_results['stats']
            section += f"- **Start Time:** {stats['start_time']}\n"
            section += f"- **End Time:** {stats['end_time']}\n"
            section += f"- **Duration:** {stats['time_span']}\n"
            section += f"- **Total Events Analyzed:** {stats['total_events']}\n\n"
        else:
            section += f"- **Total Events Analyzed:** {len(logs_df)}\n"
            section += f"- **Time Range:** {logs_df['timestamp'].min()} to {logs_df['timestamp'].max()}\n\n"
        
        section += "### Affected Assets\n\n"
        
        if anomaly_df is not None:
            # Get anomalous events
            anomalous = anomaly_df[anomaly_df['is_anomaly'] == 1]
            
            # Affected users
            affected_users = anomalous['user'].value_counts().head(5)
            section += "**Most Affected Users:**\n\n"
            for user, count in affected_users.items():
                if user != 'UNKNOWN':
                    section += f"- `{user}` ({count} suspicious events)\n"
            
            section += "\n**Source IP Addresses:**\n\n"
            # Suspicious IPs
            suspicious_ips = anomalous['ip_address'].value_counts().head(5)
            for ip, count in suspicious_ips.items():
                if ip != 'UNKNOWN':
                    section += f"- `{ip}` ({count} suspicious events)\n"
            
            section += "\n**Targeted Resources:**\n\n"
            # Targeted resources
            resources = anomalous['resource'].value_counts().head(5)
            for resource, count in resources.items():
                if resource != 'UNKNOWN':
                    section += f"- `{resource}` ({count} accesses)\n"
        
        return section
    
    def _generate_technical_analysis(self, anomaly_df, correlation_results, timeline_results):
        """Generate technical analysis section"""
        section = "## 🔬 TECHNICAL ANALYSIS\n\n"
        
        # Anomaly detection results
        if anomaly_df is not None:
            section += "### Anomaly Detection Results\n\n"
            
            section += "**Machine Learning Model:** Isolation Forest (Unsupervised)\n\n"
            
            anomalies = anomaly_df[anomaly_df['is_anomaly'] == 1]
            section += f"**Detection Statistics:**\n\n"
            section += f"- Total events analyzed: {len(anomaly_df)}\n"
            section += f"- Anomalies detected: {len(anomalies)}\n"
            section += f"- Detection rate: {(len(anomalies)/len(anomaly_df)*100):.2f}%\n"
            section += f"- Average anomaly score: {anomaly_df['anomaly_score'].mean():.3f}\n"
            section += f"- Maximum anomaly score: {anomaly_df['anomaly_score'].max():.3f}\n\n"
            
            section += "**Severity Distribution:**\n\n"
            severity_counts = anomaly_df['severity_level'].value_counts()
            for severity, count in severity_counts.items():
                pct = (count / len(anomaly_df)) * 100
                section += f"- {severity}: {count} events ({pct:.1f}%)\n"
        
        section += "\n"
        
        # Attack chain analysis
        if correlation_results and correlation_results['attack_chains_detected'] > 0:
            section += "### Attack Chain Analysis\n\n"
            
            chains = correlation_results['attack_chains']
            section += f"**Correlated Attack Chains:** {len(chains)}\n\n"
            
            for i, chain in enumerate(chains[:3], 1):  # Show top 3 chains
                section += f"#### Chain {i}: {chain['pattern']}\n\n"
                section += f"- **Severity:** {chain['severity']}\n"
                section += f"- **Events:** {chain['event_count']}\n"
                section += f"- **Duration:** {chain['duration']:.0f} seconds\n"
                section += f"- **Primary Source:** `{chain['primary_ip']}`\n"
                section += f"- **Max Anomaly Score:** {chain['max_anomaly_score']:.2f}\n\n"
                
                section += "**Event Sequence:**\n\n"
                for j, event in enumerate(chain['events'][:5], 1):  # Show first 5 events
                    section += f"{j}. `{event['action']}` by `{event['user']}` "
                    section += f"(Score: {event['anomaly_score']:.2f})\n"
                
                section += "\n"
        
        # Kill chain analysis
        if timeline_results:
            section += "### Cyber Kill Chain Analysis\n\n"
            
            phase_dist = timeline_results['phase_distribution']
            section += "**Attack Phases Observed:**\n\n"
            
            for phase, count in sorted(phase_dist.items(), key=lambda x: x[1], reverse=True):
                if phase != 'Unknown':
                    section += f"- **{phase}**: {count} events\n"
        
        return section
    
    
    def _generate_prediction_section(self, prediction_results):
        """Generate attack prediction section"""
        section = "## 🔮 ATTACK PREDICTION & THREAT INTELLIGENCE\n\n"
    
        # Identified attacks
        if 'detected_attacks' in prediction_results and prediction_results['detected_attacks']:
            section += "### 🎯 Identified Attack Types\n\n"
        
            for attack in prediction_results['detected_attacks']:
                severity_icon = "🔴" if attack['severity'] == 'CRITICAL' else "🟠" if attack['severity'] == 'HIGH' else "🟡"
                section += f"#### {severity_icon} {attack['attack_name']}\n\n"
                section += f"- **Confidence:** {attack['confidence']:.0%}\n"
                section += f"- **Severity:** {attack['severity']}\n"
                section += f"- **Attack ID:** `{attack['attack_id']}`\n"
                section += f"- **Detection Reason:** {attack['reason']}\n\n"
    
        # Next stage prediction
        if 'next_stage_prediction' in prediction_results:
            pred = prediction_results['next_stage_prediction']
        
            section += "### 📊 Next Stage Prediction\n\n"
        
            if pred.get('next_stage', {}).get('stage_name'):
                section += f"**Predicted Next Stage:** {pred['next_stage']['stage_name']}\n"
                section += f"**Probability:** {pred['next_stage']['probability']}\n"
                section += f"**Severity if Reached:** {pred['next_stage']['severity']}\n\n"
            
                # Timing
                if 'timing' in pred:
                    timing = pred['timing']
                    section += "**Estimated Timing:**\n\n"
                    section += f"- Earliest: {timing['predicted_time_window']['earliest']}\n"
                    section += f"- Most Likely: {timing['predicted_time_window']['most_likely']}\n"
                    section += f"- Latest: {timing['predicted_time_window']['latest']}\n"
                    section += f"- Detection Window Remaining: **{timing['detection_window_remaining']} minutes**\n\n"
            
                # Target prediction
                if 'likely_targets' in pred:
                    target = pred['likely_targets']
                    if target.get('primary'):
                        section += "**Likely Target:**\n\n"
                        section += f"- Primary Target: **{target['primary']}**\n"
                        section += f"- Probability: {target['probability']}\n"
                        section += f"- Estimated Damage: {target['estimated_damage']}\n\n"
    
        # Point of no return
        if 'point_of_no_return' in prediction_results:
            ponr = prediction_results['point_of_no_return']
        
            section += "### ⚠️ Point of No Return Analysis\n\n"
        
            if ponr['can_still_stop']:
                section += f"**Status:** {ponr['status']} - Attack can still be stopped\n"
                section += f"**Time Remaining:** {ponr['minutes_remaining']} minutes until point of no return\n"
                section += f"**Stages Remaining:** {ponr['stages_remaining']}\n"
                section += f"**Critical Time:** {ponr['critical_time']}\n\n"
            else:
                section += "🚨 **CRITICAL WARNING:** Attack has reached or passed the point of no return.\n\n"
                section += "Immediate containment and recovery actions are required.\n\n"
    
        # Attacker profile
        if 'attacker_profile' in prediction_results:
            profile = prediction_results['attacker_profile']
        
            section += "### 👤 Attacker Profile\n\n"
        
            if 'identified_attacker' in profile:
                attacker = profile['identified_attacker']
                section += f"**Identified Type:** {attacker['type']}\n"
                section += f"**Confidence:** {attacker['confidence']}\n"
                section += f"**Skill Level:** {attacker['skill_level']}\n"
                section += f"**Sophistication:** {attacker['sophistication']}\n\n"
        
            if 'expected_behaviors' in profile:
                behaviors = profile['expected_behaviors']
                section += "**Expected Behaviors:**\n\n"
                section += f"- Prefers Stealth: {behaviors['prefers_stealth']}\n"
                section += f"- Covers Tracks: {behaviors['covers_tracks']}\n"
                section += f"- Typical Duration: {behaviors['typical_duration']}\n"
                section += f"- Success Rate: {behaviors['success_rate']}\n\n"
        
            if 'likely_next_actions' in profile:
                section += "**Likely Next Actions:**\n\n"
                for action in profile['likely_next_actions'][:5]:
                    section += f"- {action}\n"
                section += "\n"
    
        # Recommended actions from playbook
        if 'recommended_actions' in prediction_results:
            section += "### 🛡️ Playbook-Based Countermeasures\n\n"
        
            for i, action in enumerate(prediction_results['recommended_actions'], 1):
                section += f"**{i}. {action['action']}**\n"
                section += f"- Effectiveness: {action['effectiveness']}\n"
                section += f"- Implementation Time: {action['time']}\n"
                if 'countermeasure_id' in action and action['countermeasure_id']:
                    section += f"- Countermeasure ID: `{action['countermeasure_id']}`\n"
                section += "\n"
    
        return section
    def _generate_timeline_section(self, timeline_results):
        """Generate attack timeline section"""
        section = "## ⏱️ ATTACK TIMELINE\n\n"

        if not timeline_results:
            section += "Timeline narrative not available."
            return section

        section += timeline_results.get(
            'narrative',
            'Timeline narrative not available.'
        )

        return section

    
    def _generate_evidence_summary(self, anomaly_df, correlation_results):
        """Generate evidence summary"""
        section = "## 📁 EVIDENCE SUMMARY\n\n"
        
        if anomaly_df is not None:
            anomalies = anomaly_df[anomaly_df['is_anomaly'] == 1].sort_values(
                'anomaly_score', ascending=False
            )
            
            section += f"### Top 10 Most Suspicious Events\n\n"
            
            for i, (idx, event) in enumerate(anomalies.head(10).iterrows(), 1):
                section += f"#### Evidence #{i}\n\n"
                section += f"- **Event ID:** `{event['event_id']}`\n"
                section += f"- **Timestamp:** {event['timestamp']}\n"
                section += f"- **Action:** `{event['action']}`\n"
                section += f"- **User:** `{event['user']}`\n"
                section += f"- **Source IP:** `{event['ip_address']}`\n"
                section += f"- **Resource:** `{event['resource']}`\n"
                section += f"- **Result:** {event['result']}\n"
                section += f"- **Anomaly Score:** {event['anomaly_score']:.3f}\n"
                section += f"- **Severity:** {event['severity_level']}\n"
                
                if event['explanation']:
                    section += f"- **Why Suspicious:** {event['explanation']}\n"
                
                section += "\n"
        
        return section
    
    def _generate_ioc_section(self, anomaly_df):
        """Generate Indicators of Compromise section"""
        section = "## 🚩 INDICATORS OF COMPROMISE (IOCs)\n\n"
        
        if anomaly_df is not None:
            anomalies = anomaly_df[anomaly_df['is_anomaly'] == 1]
            
            # Malicious IPs
            section += "### Suspicious IP Addresses\n\n"
            suspicious_ips = anomalies['ip_address'].value_counts().head(10)
            for ip, count in suspicious_ips.items():
                if ip != 'UNKNOWN' and not self._is_internal_ip(ip):
                    section += f"- `{ip}` ({count} malicious events)\n"
            
            section += "\n### Compromised Accounts\n\n"
            # Compromised users
            compromised_users = anomalies['user'].value_counts().head(10)
            for user, count in compromised_users.items():
                if user != 'UNKNOWN':
                    section += f"- `{user}` ({count} suspicious activities)\n"
            
            section += "\n### Malicious Actions\n\n"
            # Malicious actions
            malicious_actions = anomalies['action'].value_counts().head(10)
            for action, count in malicious_actions.items():
                section += f"- `{action}` ({count} occurrences)\n"
            
            section += "\n### Targeted Resources\n\n"
            # Targeted resources
            targeted = anomalies['resource'].value_counts().head(10)
            for resource, count in targeted.items():
                if resource != 'UNKNOWN':
                    section += f"- `{resource}` ({count} suspicious accesses)\n"
        
        return section
    
    def _generate_confidence_assessment(self, anomaly_df, correlation_results):
        """Generate confidence assessment"""
        section = "## 🎯 CONFIDENCE ASSESSMENT\n\n"
        
        # Calculate overall confidence
        confidence_factors = []
        
        if anomaly_df is not None:
            # ML model confidence
            avg_score = anomaly_df[anomaly_df['is_anomaly'] == 1]['anomaly_score'].mean()
            ml_confidence = avg_score * 100
            confidence_factors.append(('ML Model Confidence', ml_confidence))
            
            section += f"**Machine Learning Confidence:** {ml_confidence:.1f}%\n\n"
        
        if correlation_results and correlation_results['attack_chains_detected'] > 0:
            # Correlation confidence
            chain_confidence = min(correlation_results['attack_chains_detected'] * 15, 95)
            confidence_factors.append(('Chain Correlation', chain_confidence))
            
            section += f"**Attack Chain Correlation:** {chain_confidence:.1f}%\n\n"
        
        # Overall confidence
        if confidence_factors:
            overall_confidence = np.mean([c[1] for c in confidence_factors])
            
            section += f"### Overall Analysis Confidence: **{overall_confidence:.1f}%**\n\n"
            
            if overall_confidence >= 85:
                section += "✅ **HIGH CONFIDENCE** - Findings are highly reliable\n\n"
            elif overall_confidence >= 70:
                section += "⚠️ **MEDIUM CONFIDENCE** - Findings are moderately reliable\n\n"
            else:
                section += "⚠️ **LOW CONFIDENCE** - Additional investigation recommended\n\n"
        
        section += "**Confidence Factors:**\n\n"
        for factor, score in confidence_factors:
            section += f"- {factor}: {score:.1f}%\n"
        
        return section
    
    def _generate_recommendations(self, anomaly_df, correlation_results, timeline_results):
        """Generate recommendations section"""
        section = "## 💡 RECOMMENDATIONS\n\n"
        
        section += "### Immediate Actions\n\n"
        
        if anomaly_df is not None:
            critical = (anomaly_df['severity_level'] == 'CRITICAL').sum()
            
            if critical > 0:
                section += "1. **URGENT:** Isolate affected systems from the network\n"
                section += "2. **URGENT:** Reset credentials for all compromised accounts\n"
                section += "3. **URGENT:** Initiate full incident response procedures\n"
                section += "4. **URGENT:** Preserve evidence for forensic analysis\n"
            else:
                section += "1. Review all flagged anomalous events with security team\n"
                section += "2. Verify legitimacy of suspicious activities\n"
                section += "3. Monitor affected accounts for further suspicious behavior\n"
        
        section += "\n### Short-Term Actions (24-48 hours)\n\n"
        section += "1. Conduct comprehensive security audit of affected systems\n"
        section += "2. Review and update access control policies\n"
        section += "3. Enable enhanced logging and monitoring\n"
        section += "4. Scan all systems for malware and backdoors\n"
        section += "5. Update incident response documentation\n"
        
        section += "\n### Long-Term Actions\n\n"
        section += "1. Implement multi-factor authentication (MFA) for all accounts\n"
        section += "2. Deploy Security Information and Event Management (SIEM) solution\n"
        section += "3. Conduct regular security awareness training\n"
        section += "4. Perform regular penetration testing\n"
        section += "5. Implement least-privilege access principles\n"
        section += "6. Establish continuous security monitoring program\n"
        
        section += "\n### Technical Hardening\n\n"
        
        if timeline_results:
            phases = timeline_results.get('phase_distribution', {})
            
            if 'Privilege Escalation' in phases:
                section += "- 🔒 Implement privilege access management (PAM)\n"
            
            if 'Exfiltration' in phases:
                section += "- 🛡️ Deploy data loss prevention (DLP) controls\n"
            
            if 'Defense Evasion' in phases:
                section += "- 📊 Enable tamper-proof logging with write-once-read-many (WORM) storage\n"
        
        section += "- 🔐 Enable endpoint detection and response (EDR) on all systems\n"
        section += "- 🚧 Implement network segmentation\n"
        section += "- 🔍 Deploy intrusion detection/prevention systems (IDS/IPS)\n"
        
        return section
    
    def _generate_appendix(self, log_stats):
        """Generate appendix with technical details"""
        section = "## 📎 APPENDIX\n\n"
        
        section += "### A. Methodology\n\n"
        section += "**Analysis Framework:** AI-Based Log Investigation Framework\n\n"
        section += "**Techniques Used:**\n\n"
        section += "- Unsupervised Machine Learning (Isolation Forest)\n"
        section += "- Graph-based Event Correlation (NetworkX)\n"
        section += "- Temporal Pattern Analysis\n"
        section += "- Cyber Kill Chain Mapping\n"
        section += "- Behavioral Anomaly Detection\n\n"
        
        if log_stats:
            section += "### B. Data Sources\n\n"
            section += f"- Total events ingested: {log_stats.get('total_events', 'N/A')}\n"
            section += f"- Unique users: {log_stats.get('unique_users', 'N/A')}\n"
            section += f"- Unique IP addresses: {log_stats.get('unique_ips', 'N/A')}\n"
            section += f"- Data quality: {100 - log_stats.get('missing_data_percentage', 0):.1f}%\n"
        
        section += "\n### C. Model Parameters\n\n"
        section += "- **Anomaly Detection:** Isolation Forest with auto-tuned contamination\n"
        section += "- **Feature Engineering:** 20+ behavioral and statistical features\n"
        section += "- **Correlation Window:** 30-minute sliding window\n"
        section += "- **Confidence Threshold:** 0.6 for anomaly classification\n"
        
        return section
    
    def _generate_footer(self):
        """Generate report footer"""
        footer = f"""---

## 📝 REPORT METADATA

- **Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **Tool:** {self.report_metadata['tool_name']}
- **Version:** {self.report_metadata['version']}
- **Analyst:** {self.report_metadata['analyst']}

---

**DISCLAIMER:** This report was generated by an automated AI-powered forensic analysis system. 
All findings should be verified by qualified security professionals. The confidence scores 
represent statistical likelihood and should not be considered definitive proof.

**CONFIDENTIALITY NOTICE:** This report contains sensitive security information and should 
be handled according to your organization's information security policies.

---

*End of Report*
"""
        return footer
    
    def _is_internal_ip(self, ip):
        """Check if IP is internal (private range)"""
        if pd.isna(ip) or ip == 'UNKNOWN':
            return True
        
        private_patterns = ['10.', '172.', '192.168.', '127.', 'localhost']
        
        for pattern in private_patterns:
            if str(ip).startswith(pattern):
                return True
        
        return False


# Helper function for easy import
def generate_forensic_report(logs_df, anomaly_df=None, correlation_results=None, 
                             timeline_results=None, log_stats=None, prediction_results=None):
    """
    Convenience function to generate forensic report
    
    Args:
        logs_df: Original logs DataFrame
        anomaly_df: Anomaly detection results
        correlation_results: Event correlation results
        timeline_results: Timeline analysis results
        log_stats: Log parsing statistics
        prediction_results: Attack prediction results
        
    Returns:
        str: Complete forensic report in Markdown
    """
    generator = ForensicReportGenerator()
    report = generator.generate_report(
        logs_df, anomaly_df, correlation_results, timeline_results, log_stats, prediction_results
    )
    
    return report