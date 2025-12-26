"""
Event Correlation Module
Links related events into attack chains using graph-based analysis
"""

import pandas as pd
import networkx as nx
from datetime import timedelta
import numpy as np

class EventCorrelator:
    """
    Correlates events to identify multi-stage attack chains
    Uses graph-based analysis with NetworkX
    """
    
    def __init__(self, time_window_minutes=30):
        """
        Initialize the event correlator
        
        Args:
            time_window_minutes: Time window for linking events (default: 30 min)
        """
        self.time_window = timedelta(minutes=time_window_minutes)
        self.graph = None
        self.attack_chains = []
        
        # Define attack patterns (sequence of actions that indicate attacks)
        self.attack_patterns = {
            'Credential_Brute_Force': [
                'FAILED_LOGIN', 'FAILED_LOGIN', 'SUCCESS_LOGIN'
            ],
            'Privilege_Escalation_Attack': [
                'LOGIN', 'PRIVILEGE_ESCALATION', 'FILE_ACCESS'
            ],
            'Data_Exfiltration': [
                'FILE_ACCESS', 'FILE_DOWNLOAD', 'FILE_DELETE'
            ],
            'Reconnaissance_to_Exploit': [
                'PORT_SCAN', 'LOGIN', 'EXPLOIT'
            ],
            'SQL_Injection_Attack': [
                'SQL_INJECTION_ATTEMPT', 'DATABASE_QUERY', 'DATA_EXTRACTION'
            ],
            'Malware_Execution': [
                'FILE_UPLOAD', 'THREAT_DETECTED', 'FILE_EXECUTION'
            ]
        }
        
        # High-risk action combinations
        self.high_risk_sequences = [
            ('PRIVILEGE_ESCALATION', 'FILE_ACCESS'),
            ('LOGIN', 'FILE_DELETE'),
            ('FILE_ACCESS', 'FILE_DOWNLOAD'),
            ('CONFIG_CHANGE', 'SERVICE_RESTART'),
            ('USER_CREATE', 'PRIVILEGE_ESCALATION')
        ]
    
    def correlate_events(self, df, anomaly_df=None):
        """
        Main correlation function - links events into attack chains
        
        Args:
            df: Original DataFrame with logs
            anomaly_df: DataFrame with anomaly scores (optional)
            
        Returns:
            dict: Correlation results with attack chains
        """
        # Use anomaly dataframe if provided
        working_df = anomaly_df if anomaly_df is not None else df.copy()
        
        # Ensure we have anomaly scores
        if 'anomaly_score' not in working_df.columns:
            working_df['anomaly_score'] = 0.5  # Default medium score
        
        # Build correlation graph
        self.graph = self._build_correlation_graph(working_df)
        
        # Detect attack chains
        self.attack_chains = self._detect_attack_chains(working_df)
        
        # Compile results
        results = {
            'total_events': len(working_df),
            'correlated_events': len([n for n in self.graph.nodes() if self.graph.degree(n) > 0]),
            'attack_chains_detected': len(self.attack_chains),
            'unique_attackers': len(self._get_unique_attackers(working_df)),
            'graph': self.graph,
            'attack_chains': self.attack_chains
        }
        
        return results
    
    def _build_correlation_graph(self, df):
        """
        Build a directed graph connecting related events
        
        Args:
            df: DataFrame with logs
            
        Returns:
            nx.DiGraph: Directed graph of correlated events
        """
        G = nx.DiGraph()
        
        # Add all events as nodes
        for idx, row in df.iterrows():
            G.add_node(
                row['event_id'],
                timestamp=row['timestamp'],
                user=row['user'],
                action=row['action'],
                ip_address=row['ip_address'],
                resource=row['resource'],
                result=row['result'],
                anomaly_score=row.get('anomaly_score', 0.5),
                severity=row.get('severity_level', 'UNKNOWN')
            )
        
        # Connect related events with edges
        for i, event1 in df.iterrows():
            for j, event2 in df.iterrows():
                if i >= j:
                    continue  # Only forward connections
                
                # Check if events should be linked
                if self._should_link_events(event1, event2):
                    # Calculate edge weight (correlation strength)
                    weight = self._calculate_correlation_strength(event1, event2)
                    
                    G.add_edge(
                        event1['event_id'],
                        event2['event_id'],
                        weight=weight,
                        time_delta=(event2['timestamp'] - event1['timestamp']).total_seconds()
                    )
        
        return G
    
    def _should_link_events(self, event1, event2):
        """
        Determine if two events should be linked
        
        Args:
            event1, event2: Event rows from DataFrame
            
        Returns:
            bool: True if events should be linked
        """
        # Events must be within time window
        time_diff = event2['timestamp'] - event1['timestamp']
        if time_diff > self.time_window or time_diff < timedelta(0):
            return False
        
        # Link if same user
        if event1['user'] == event2['user'] and event1['user'] != 'UNKNOWN':
            return True
        
        # Link if same IP address
        if event1['ip_address'] == event2['ip_address'] and event1['ip_address'] != 'UNKNOWN':
            return True
        
        # Link if same resource
        if event1['resource'] == event2['resource'] and event1['resource'] != 'UNKNOWN':
            return True
        
        # Link if high-risk sequence
        action_pair = (event1['action'], event2['action'])
        if action_pair in self.high_risk_sequences:
            return True
        
        # Link if both are anomalies from similar source
        if (event1.get('anomaly_score', 0) > 0.6 and 
            event2.get('anomaly_score', 0) > 0.6):
            if event1['ip_address'] == event2['ip_address']:
                return True
        
        return False
    
    def _calculate_correlation_strength(self, event1, event2):
        """
        Calculate how strongly two events are correlated (0-1)
        
        Args:
            event1, event2: Event rows
            
        Returns:
            float: Correlation strength
        """
        strength = 0.0
        
        # Same user increases correlation
        if event1['user'] == event2['user']:
            strength += 0.3
        
        # Same IP increases correlation
        if event1['ip_address'] == event2['ip_address']:
            strength += 0.3
        
        # High anomaly scores increase correlation
        avg_anomaly = (event1.get('anomaly_score', 0) + event2.get('anomaly_score', 0)) / 2
        strength += avg_anomaly * 0.2
        
        # Close time proximity increases correlation
        time_diff = (event2['timestamp'] - event1['timestamp']).total_seconds()
        if time_diff < 300:  # Within 5 minutes
            strength += 0.2
        
        return min(strength, 1.0)
    
    def _detect_attack_chains(self, df):
        """
        Detect attack chains from the correlation graph
        
        Args:
            df: DataFrame with logs
            
        Returns:
            list: List of attack chain dictionaries
        """
        chains = []
        
        # Find connected components (groups of related events)
        if self.graph.number_of_edges() == 0:
            return chains
        
        # Convert to undirected for component detection
        undirected = self.graph.to_undirected()
        components = list(nx.connected_components(undirected))
        
        # Analyze each component
        for component in components:
            if len(component) < 2:
                continue  # Skip single events
            
            # Extract subgraph for this chain
            subgraph = self.graph.subgraph(component)
            
            # Get events in chronological order
            event_ids = sorted(
                component,
                key=lambda eid: self.graph.nodes[eid]['timestamp']
            )
            
            # Build chain information
            chain_events = [self.graph.nodes[eid] for eid in event_ids]
            
            # Calculate chain severity
            avg_anomaly_score = np.mean([e['anomaly_score'] for e in chain_events])
            max_anomaly_score = max([e['anomaly_score'] for e in chain_events])
            
            # Identify attack pattern
            pattern = self._identify_attack_pattern(chain_events)
            
            # Determine chain severity
            if max_anomaly_score >= 0.8 or len(chain_events) >= 5:
                chain_severity = "CRITICAL"
            elif max_anomaly_score >= 0.6 or len(chain_events) >= 3:
                chain_severity = "HIGH"
            elif max_anomaly_score >= 0.4:
                chain_severity = "MEDIUM"
            else:
                chain_severity = "LOW"
            
            # Get primary attacker (most frequent IP or user)
            ip_counts = {}
            for event in chain_events:
                ip = event['ip_address']
                if ip != 'UNKNOWN':
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
            
            primary_ip = max(ip_counts.items(), key=lambda x: x[1])[0] if ip_counts else 'UNKNOWN'
            
            # Build chain object
            chain = {
                'chain_id': f"CHAIN_{len(chains)+1:03d}",
                'event_count': len(chain_events),
                'events': chain_events,
                'event_ids': event_ids,
                'severity': chain_severity,
                'avg_anomaly_score': avg_anomaly_score,
                'max_anomaly_score': max_anomaly_score,
                'pattern': pattern,
                'primary_ip': primary_ip,
                'start_time': chain_events[0]['timestamp'],
                'end_time': chain_events[-1]['timestamp'],
                'duration': (chain_events[-1]['timestamp'] - chain_events[0]['timestamp']).total_seconds(),
                'actions': [e['action'] for e in chain_events],
                'users': list(set([e['user'] for e in chain_events if e['user'] != 'UNKNOWN']))
            }
            
            chains.append(chain)
        
        # Sort chains by severity and anomaly score
        chains.sort(key=lambda x: (
            ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].index(x['severity']),
            x['max_anomaly_score']
        ), reverse=True)
        
        return chains
    
    def _identify_attack_pattern(self, chain_events):
        """
        Identify if chain matches known attack patterns
        
        Args:
            chain_events: List of events in the chain
            
        Returns:
            str: Attack pattern name or "Unknown Pattern"
        """
        actions = [e['action'] for e in chain_events]
        
        # Check for brute force (multiple failures then success)
        if actions.count('LOGIN') >= 3:
            results = [e['result'] for e in chain_events if e['action'] == 'LOGIN']
            if 'FAILED' in results and 'SUCCESS' in results:
                return "Credential Brute Force"
        
        # Check for privilege escalation
        if 'PRIVILEGE_ESCALATION' in actions:
            return "Privilege Escalation Attack"
        
        # Check for data exfiltration
        if 'FILE_DOWNLOAD' in actions and 'FILE_ACCESS' in actions:
            if any('sensitive' in e['resource'].lower() for e in chain_events):
                return "Data Exfiltration"
        
        # Check for reconnaissance
        if 'PORT_SCAN' in actions:
            return "Reconnaissance Activity"
        
        # Check for SQL injection
        if 'SQL_INJECTION_ATTEMPT' in actions:
            return "SQL Injection Attack"
        
        # Check for malware
        if 'THREAT_DETECTED' in actions or 'MALWARE' in actions:
            return "Malware Activity"
        
        # Check for log tampering
        if 'FILE_DELETE' in actions:
            if any('log' in e['resource'].lower() for e in chain_events):
                return "Log Tampering"
        
        # Generic multi-stage attack
        if len(chain_events) >= 3:
            return "Multi-Stage Attack"
        
        return "Suspicious Activity"
    
    def _get_unique_attackers(self, df):
        """Get unique attacker IP addresses"""
        # Consider external IPs with anomalies as attackers
        attackers = set()
        
        for _, row in df.iterrows():
            if row.get('anomaly_score', 0) > 0.5:
                ip = row['ip_address']
                if ip != 'UNKNOWN' and not self._is_internal_ip(ip):
                    attackers.add(ip)
        
        return attackers
    
    def _is_internal_ip(self, ip):
        """Check if IP is internal (private range)"""
        if pd.isna(ip) or ip == 'UNKNOWN':
            return True
        
        # Private IP ranges
        private_patterns = ['10.', '172.', '192.168.', '127.', 'localhost']
        
        for pattern in private_patterns:
            if str(ip).startswith(pattern):
                return True
        
        return False
    
    def get_chain_summary(self, chain):
        """
        Generate human-readable summary of an attack chain
        
        Args:
            chain: Attack chain dictionary
            
        Returns:
            str: Summary text
        """
        summary = f"""
**{chain['pattern']}** ({chain['severity']} Severity)

**Chain ID:** {chain['chain_id']}
**Events:** {chain['event_count']} correlated events
**Duration:** {chain['duration']:.0f} seconds
**Time Range:** {chain['start_time']} to {chain['end_time']}
**Primary Source:** {chain['primary_ip']}
**Users Involved:** {', '.join(chain['users']) if chain['users'] else 'Unknown'}
**Max Anomaly Score:** {chain['max_anomaly_score']:.2f}

**Event Sequence:**
"""
        
        for i, event in enumerate(chain['events'], 1):
            summary += f"{i}. [{event['timestamp']}] {event['action']} by {event['user']} "
            summary += f"(Score: {event['anomaly_score']:.2f})\n"
        
        return summary


# Helper function for easy import
def correlate_events(df, anomaly_df=None, time_window=30):
    """
    Convenience function to correlate events
    
    Args:
        df: Original DataFrame with logs
        anomaly_df: DataFrame with anomaly scores
        time_window: Time window in minutes for correlation
        
    Returns:
        tuple: (results_dict, attack_chains_list)
    """
    correlator = EventCorrelator(time_window_minutes=time_window)
    results = correlator.correlate_events(df, anomaly_df)
    
    return results, results['attack_chains']