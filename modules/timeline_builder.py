"""
Timeline Builder Module
Reconstructs chronological attack timeline with phase classification
"""

import pandas as pd
from datetime import datetime, timedelta
import numpy as np

class TimelineBuilder:
    """
    Builds chronological timeline of events with attack phase classification
    Maps events to cyber kill chain phases
    """
    
    def __init__(self):
        """Initialize the timeline builder"""
        
        # Cyber Kill Chain phases (simplified)
        self.kill_chain_phases = [
            'Reconnaissance',
            'Initial Access',
            'Execution',
            'Persistence',
            'Privilege Escalation',
            'Defense Evasion',
            'Credential Access',
            'Discovery',
            'Lateral Movement',
            'Collection',
            'Exfiltration',
            'Impact'
        ]
        
        # Action to Kill Chain phase mapping
        self.action_to_phase = {
            # Reconnaissance
            'PORT_SCAN': 'Reconnaissance',
            'NETWORK_SCAN': 'Reconnaissance',
            'VULNERABILITY_SCAN': 'Reconnaissance',
            'RECONNAISSANCE': 'Reconnaissance',
            
            # Initial Access
            'LOGIN': 'Initial Access',
            'VPN_CONNECT': 'Initial Access',
            'REMOTE_ACCESS': 'Initial Access',
            'EXPLOIT': 'Initial Access',
            'SQL_INJECTION_ATTEMPT': 'Initial Access',
            'BRUTE_FORCE': 'Initial Access',
            
            # Execution
            'COMMAND_EXECUTION': 'Execution',
            'SCRIPT_EXECUTION': 'Execution',
            'FILE_EXECUTION': 'Execution',
            'PROCESS_CREATE': 'Execution',
            'MALWARE': 'Execution',
            'THREAT_DETECTED': 'Execution',
            
            # Persistence
            'SERVICE_INSTALL': 'Persistence',
            'REGISTRY_MODIFY': 'Persistence',
            'SCHEDULED_TASK': 'Persistence',
            'STARTUP_ITEM': 'Persistence',
            
            # Privilege Escalation
            'PRIVILEGE_ESCALATION': 'Privilege Escalation',
            'SUDO': 'Privilege Escalation',
            'UAC_BYPASS': 'Privilege Escalation',
            
            # Defense Evasion
            'FILE_DELETE': 'Defense Evasion',
            'LOG_CLEAR': 'Defense Evasion',
            'ANTIVIRUS_DISABLE': 'Defense Evasion',
            'PROCESS_INJECTION': 'Defense Evasion',
            
            # Credential Access
            'PASSWORD_DUMP': 'Credential Access',
            'CREDENTIAL_ACCESS': 'Credential Access',
            'KEYLOGGING': 'Credential Access',
            
            # Discovery
            'SYSTEM_INFO': 'Discovery',
            'NETWORK_DISCOVERY': 'Discovery',
            'ACCOUNT_DISCOVERY': 'Discovery',
            'FILE_DISCOVERY': 'Discovery',
            
            # Lateral Movement
            'REMOTE_SERVICE': 'Lateral Movement',
            'REMOTE_DESKTOP': 'Lateral Movement',
            'SSH_LATERAL': 'Lateral Movement',
            
            # Collection
            'FILE_ACCESS': 'Collection',
            'DATABASE_QUERY': 'Collection',
            'DATA_STAGED': 'Collection',
            'SCREEN_CAPTURE': 'Collection',
            
            # Exfiltration
            'FILE_DOWNLOAD': 'Exfiltration',
            'FILE_UPLOAD': 'Exfiltration',
            'DATA_TRANSFER': 'Exfiltration',
            'EXFILTRATION': 'Exfiltration',
            
            # Impact
            'DATA_DESTRUCTION': 'Impact',
            'SERVICE_STOP': 'Impact',
            'RANSOMWARE': 'Impact',
            'DEFACEMENT': 'Impact'
        }
        
        # Phase colors for visualization
        self.phase_colors = {
            'Reconnaissance': '#7fdbff',
            'Initial Access': '#0074d9',
            'Execution': '#ff851b',
            'Persistence': '#b10dc9',
            'Privilege Escalation': '#ff4136',
            'Defense Evasion': '#85144b',
            'Credential Access': '#f012be',
            'Discovery': '#39cccc',
            'Lateral Movement': '#3d9970',
            'Collection': '#2ecc40',
            'Exfiltration': '#ffdc00',
            'Impact': '#ff4136',
            'Unknown': '#aaaaaa'
        }
    
    def build_timeline(self, df, anomaly_df=None, attack_chains=None):
        """
        Build comprehensive timeline from logs
        
        Args:
            df: Original DataFrame with logs
            anomaly_df: DataFrame with anomaly scores (optional)
            attack_chains: List of detected attack chains (optional)
            
        Returns:
            dict: Timeline data and statistics
        """
        # Use anomaly dataframe if provided
        working_df = anomaly_df if anomaly_df is not None else df.copy()
        
        # Ensure we have necessary columns
        if 'anomaly_score' not in working_df.columns:
            working_df['anomaly_score'] = 0.5
        
        # Sort by timestamp
        timeline_df = working_df.sort_values('timestamp').reset_index(drop=True)
        
        # Classify phases
        timeline_df['kill_chain_phase'] = timeline_df['action'].apply(
            self._classify_phase
        )
        
        # Add sequence numbers
        timeline_df['sequence'] = range(1, len(timeline_df) + 1)
        
        # Identify time gaps (potential distinct attack sessions)
        timeline_df['time_gap'] = timeline_df['timestamp'].diff()
        timeline_df['session_boundary'] = (
            timeline_df['time_gap'] > timedelta(minutes=15)
        ).fillna(False)
        
        # Assign session IDs
        timeline_df['session_id'] = timeline_df['session_boundary'].cumsum() + 1
        
        # Calculate statistics
        stats = self._calculate_timeline_stats(timeline_df, attack_chains)
        
        # Identify critical periods
        critical_periods = self._identify_critical_periods(timeline_df)
        
        # Build timeline events for visualization
        timeline_events = self._build_timeline_events(timeline_df)
        
        results = {
            'timeline_df': timeline_df,
            'stats': stats,
            'critical_periods': critical_periods,
            'timeline_events': timeline_events,
            'phase_distribution': timeline_df['kill_chain_phase'].value_counts().to_dict(),
            'session_count': timeline_df['session_id'].max()
        }
        
        return results
    
    def _classify_phase(self, action):
        """
        Classify an action into a kill chain phase
        
        Args:
            action: Action string
            
        Returns:
            str: Kill chain phase
        """
        if pd.isna(action):
            return 'Unknown'
        
        action_upper = str(action).upper()
        
        # Direct mapping
        if action_upper in self.action_to_phase:
            return self.action_to_phase[action_upper]
        
        # Partial matching for compound actions
        for key, phase in self.action_to_phase.items():
            if key in action_upper:
                return phase
        
        # Default classification based on keywords
        if any(word in action_upper for word in ['SCAN', 'PROBE', 'RECON']):
            return 'Reconnaissance'
        elif any(word in action_upper for word in ['LOGIN', 'ACCESS', 'CONNECT']):
            return 'Initial Access'
        elif any(word in action_upper for word in ['EXECUTE', 'RUN', 'START']):
            return 'Execution'
        elif any(word in action_upper for word in ['ESCALATE', 'ELEVATE', 'ADMIN']):
            return 'Privilege Escalation'
        elif any(word in action_upper for word in ['DELETE', 'REMOVE', 'CLEAR', 'HIDE']):
            return 'Defense Evasion'
        elif any(word in action_upper for word in ['FILE', 'DATA', 'READ']):
            return 'Collection'
        elif any(word in action_upper for word in ['DOWNLOAD', 'UPLOAD', 'TRANSFER', 'COPY']):
            return 'Exfiltration'
        elif any(word in action_upper for word in ['DESTROY', 'ENCRYPT', 'RANSOM']):
            return 'Impact'
        
        return 'Unknown'
    
    def _calculate_timeline_stats(self, timeline_df, attack_chains):
        """
        Calculate timeline statistics
        
        Args:
            timeline_df: Timeline DataFrame
            attack_chains: List of attack chains
            
        Returns:
            dict: Statistics
        """
        stats = {
            'total_events': len(timeline_df),
            'time_span': (
                timeline_df['timestamp'].max() - timeline_df['timestamp'].min()
            ),
            'start_time': timeline_df['timestamp'].min(),
            'end_time': timeline_df['timestamp'].max(),
            'phases_observed': timeline_df['kill_chain_phase'].nunique(),
            'anomalous_events': (timeline_df['anomaly_score'] > 0.6).sum(),
            'high_risk_phases': self._count_high_risk_phases(timeline_df),
            'attack_chains': len(attack_chains) if attack_chains else 0
        }
        
        # Calculate events per hour
        if stats['time_span'].total_seconds() > 0:
            hours = stats['time_span'].total_seconds() / 3600
            stats['events_per_hour'] = len(timeline_df) / hours
        else:
            stats['events_per_hour'] = 0
        
        return stats
    
    def _count_high_risk_phases(self, timeline_df):
        """Count events in high-risk kill chain phases"""
        high_risk_phases = [
            'Privilege Escalation',
            'Defense Evasion',
            'Exfiltration',
            'Impact'
        ]
        
        return timeline_df[
            timeline_df['kill_chain_phase'].isin(high_risk_phases)
        ].shape[0]
    
    def _identify_critical_periods(self, timeline_df):
        """
        Identify time periods with high suspicious activity
        
        Args:
            timeline_df: Timeline DataFrame
            
        Returns:
            list: List of critical period dictionaries
        """
        critical_periods = []
        
        # Group by 5-minute windows
        timeline_df['time_window'] = timeline_df['timestamp'].dt.floor('5min')
        
        window_stats = timeline_df.groupby('time_window').agg({
            'anomaly_score': 'mean',
            'event_id': 'count'
        }).reset_index()
        
        window_stats.columns = ['time_window', 'avg_anomaly', 'event_count']
        
        # Identify critical windows (high anomaly score or high activity)
        critical_windows = window_stats[
            (window_stats['avg_anomaly'] > 0.6) | 
            (window_stats['event_count'] > window_stats['event_count'].quantile(0.75))
        ]
        
        for _, window in critical_windows.iterrows():
            period = {
                'start': window['time_window'],
                'end': window['time_window'] + timedelta(minutes=5),
                'avg_anomaly': window['avg_anomaly'],
                'event_count': window['event_count'],
                'severity': 'CRITICAL' if window['avg_anomaly'] > 0.8 else 'HIGH'
            }
            critical_periods.append(period)
        
        return critical_periods
    
    def _build_timeline_events(self, timeline_df):
        """
        Build timeline events for Gantt-style visualization
        
        Args:
            timeline_df: Timeline DataFrame
            
        Returns:
            list: List of timeline event dictionaries
        """
        events = []
        
        for idx, row in timeline_df.iterrows():
            # Calculate event duration (use 1 minute default)
            duration = timedelta(minutes=1)
            
            event = {
                'event_id': row['event_id'],
                'start': row['timestamp'],
                'end': row['timestamp'] + duration,
                'action': row['action'],
                'user': row['user'],
                'ip_address': row['ip_address'],
                'phase': row['kill_chain_phase'],
                'anomaly_score': row['anomaly_score'],
                'severity': row.get('severity_level', 'UNKNOWN'),
                'result': row['result'],
                'color': self.phase_colors.get(row['kill_chain_phase'], '#aaaaaa')
            }
            
            events.append(event)
        
        return events
    
    def get_phase_summary(self, timeline_df):
        """
        Generate human-readable phase summary
        
        Args:
            timeline_df: Timeline DataFrame
            
        Returns:
            str: Summary text
        """
        phase_counts = timeline_df['kill_chain_phase'].value_counts()
        
        summary = "**Attack Phase Analysis:**\n\n"
        
        for phase in self.kill_chain_phases:
            count = phase_counts.get(phase, 0)
            if count > 0:
                percentage = (count / len(timeline_df)) * 100
                summary += f"• **{phase}**: {count} events ({percentage:.1f}%)\n"
        
        return summary
    
    def get_attack_narrative(self, timeline_df, attack_chains=None):
        """
        Generate narrative description of the attack timeline
        
        Args:
            timeline_df: Timeline DataFrame
            attack_chains: List of attack chains (optional)
            
        Returns:
            str: Narrative text
        """
        narrative = "## Attack Timeline Narrative\n\n"
        
        # Opening
        start_time = timeline_df['timestamp'].min()
        end_time = timeline_df['timestamp'].max()
        duration = end_time - start_time
        
        narrative += f"**Period:** {start_time} to {end_time} "
        narrative += f"(Duration: {duration.total_seconds()/60:.0f} minutes)\n\n"
        
        # Phase progression
        phases_observed = timeline_df['kill_chain_phase'].unique()
        phases_in_order = [p for p in self.kill_chain_phases if p in phases_observed]
        
        if len(phases_in_order) >= 3:
            narrative += "### Multi-Stage Attack Detected\n\n"
            narrative += "The attacker progressed through the following phases:\n\n"
            
            for i, phase in enumerate(phases_in_order, 1):
                phase_events = timeline_df[timeline_df['kill_chain_phase'] == phase]
                first_event = phase_events.iloc[0]
                
                narrative += f"{i}. **{phase}** "
                narrative += f"(started at {first_event['timestamp']})\n"
                narrative += f"   - First action: {first_event['action']}\n"
                narrative += f"   - Total events in phase: {len(phase_events)}\n\n"
        
        # Key indicators
        high_anomaly = timeline_df[timeline_df['anomaly_score'] > 0.7]
        if len(high_anomaly) > 0:
            narrative += "### Key Indicators of Compromise\n\n"
            narrative += f"• {len(high_anomaly)} high-confidence anomalous events detected\n"
            
            if 'Privilege Escalation' in phases_observed:
                narrative += "• **Privilege escalation** indicates potential system compromise\n"
            
            if 'Exfiltration' in phases_observed:
                narrative += "• **Data exfiltration** detected - sensitive data may be compromised\n"
            
            if 'Defense Evasion' in phases_observed:
                narrative += "• **Defense evasion** tactics used - attacker attempting to hide tracks\n"
        
        return narrative


# Helper function for easy import
def build_timeline(df, anomaly_df=None, attack_chains=None):
    """
    Convenience function to build timeline
    
    Args:
        df: Original DataFrame with logs
        anomaly_df: DataFrame with anomaly scores
        attack_chains: List of attack chains
        
    Returns:
        dict: Timeline results
    """
    builder = TimelineBuilder()
    results = builder.build_timeline(df, anomaly_df, attack_chains)
    
    # Add narrative
    results['narrative'] = builder.get_attack_narrative(
        results['timeline_df'], 
        attack_chains
    )
    results['phase_summary'] = builder.get_phase_summary(results['timeline_df'])
    
    return results