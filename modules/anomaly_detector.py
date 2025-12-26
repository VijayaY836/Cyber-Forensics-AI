"""
Anomaly Detection Module
Uses Isolation Forest for unsupervised anomaly detection in logs
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

class AnomalyDetector:
    """
    Detects anomalous events in log data using machine learning
    Uses Isolation Forest algorithm for unsupervised detection
    """
    
    def __init__(self, contamination=0.1, random_state=42):
        """
        Initialize the anomaly detector
        
        Args:
            contamination: Expected proportion of outliers (0.01 to 0.5)
            random_state: Random seed for reproducibility
        """
        self.contamination = contamination
        self.random_state = random_state
        self.model = None
        self.feature_names = []
        self.label_encoders = {}
        self.feature_importance = {}
        
    def extract_features(self, df):
        """
        Extract numerical features from log data for ML
        
        Args:
            df: Normalized DataFrame with logs
            
        Returns:
            pd.DataFrame: Feature matrix for ML
        """
        features_df = pd.DataFrame()
        
        # ===== TIME-BASED FEATURES =====
        
        # Hour of day (0-23)
        features_df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
        
        # Day of week (0=Monday, 6=Sunday)
        features_df['day_of_week'] = pd.to_datetime(df['timestamp']).dt.dayofweek
        
        # Is weekend? (0 or 1)
        features_df['is_weekend'] = (features_df['day_of_week'] >= 5).astype(int)
        
        # Is business hours? (9 AM - 5 PM on weekdays)
        features_df['is_business_hours'] = (
            (features_df['hour'] >= 9) & 
            (features_df['hour'] < 17) & 
            (features_df['is_weekend'] == 0)
        ).astype(int)
        
        # Time since last event for each user (in seconds)
        df_sorted = df.sort_values('timestamp')
        features_df['time_since_last_event'] = (
            df_sorted.groupby('user')['timestamp']
            .diff()
            .dt.total_seconds()
            .fillna(0)
        )
        
        # ===== USER BEHAVIOR FEATURES =====
        
        # Encode user as numerical (frequency-based)
        user_counts = df['user'].value_counts()
        features_df['user_frequency'] = df['user'].map(user_counts).fillna(0)
        
        # Is user unknown/suspicious?
        features_df['is_unknown_user'] = df['user'].str.contains(
            'unknown|guest|anonymous', 
            case=False, 
            na=False
        ).astype(int)
        
        # ===== ACTION FEATURES =====
        
        # Encode action types
        action_encoder = LabelEncoder()
        features_df['action_encoded'] = action_encoder.fit_transform(
            df['action'].fillna('UNKNOWN')
        )
        self.label_encoders['action'] = action_encoder
        
        # Action frequency (how common is this action?)
        action_counts = df['action'].value_counts()
        features_df['action_frequency'] = df['action'].map(action_counts).fillna(0)
        
        # Is high-risk action?
        high_risk_actions = [
            'PRIVILEGE_ESCALATION', 'FILE_DELETE', 'FILE_DOWNLOAD',
            'SQL_INJECTION', 'PORT_SCAN', 'BRUTE_FORCE', 'EXPLOIT',
            'MALWARE', 'THREAT_DETECTED', 'CONFIG_CHANGE', 'USER_DELETE'
        ]
        features_df['is_high_risk_action'] = df['action'].isin(high_risk_actions).astype(int)
        
        # ===== RESULT FEATURES =====
        
        # Encode result
        result_mapping = {'SUCCESS': 1, 'FAILED': -1, 'ERROR': 0, 'UNKNOWN': 0}
        features_df['result_encoded'] = df['result'].map(result_mapping).fillna(0)
        
        # Failed login attempts (important indicator)
        features_df['is_failed'] = (df['result'] == 'FAILED').astype(int)
        
        # ===== IP ADDRESS FEATURES =====
        
        # Is external IP? (not in private ranges)
        features_df['is_external_ip'] = df['ip_address'].apply(
            self._is_external_ip
        ).astype(int)
        
        # IP frequency
        ip_counts = df['ip_address'].value_counts()
        features_df['ip_frequency'] = df['ip_address'].map(ip_counts).fillna(0)
        
        # Unique IPs per user
        user_ip_counts = df.groupby('user')['ip_address'].nunique()
        features_df['user_ip_diversity'] = df['user'].map(user_ip_counts).fillna(1)
        
        # ===== RESOURCE FEATURES =====
        
        # Is sensitive resource?
        sensitive_keywords = [
            'admin', 'root', 'sensitive', 'confidential', 'password',
            'credential', 'secret', 'private', 'financial', 'customer'
        ]
        features_df['is_sensitive_resource'] = df['resource'].str.contains(
            '|'.join(sensitive_keywords),
            case=False,
            na=False
        ).astype(int)
        
        # Resource access frequency
        resource_counts = df['resource'].value_counts()
        features_df['resource_frequency'] = df['resource'].map(resource_counts).fillna(0)
        
        # ===== SEVERITY FEATURES =====
        
        # Encode severity
        severity_mapping = {
            'INFO': 0,
            'WARNING': 1,
            'ERROR': 2,
            'CRITICAL': 3,
            'UNKNOWN': 0
        }
        features_df['severity_encoded'] = df['severity'].map(severity_mapping).fillna(0)
        
        # ===== SEQUENCE FEATURES =====
        
        # Number of events from same IP in short time window
        features_df['events_from_ip_5min'] = self._count_events_in_window(
            df, 'ip_address', minutes=5
        )
        
        # Number of failed attempts from same user
        features_df['failed_attempts_by_user'] = self._count_failed_attempts(df)
        
        # Store feature names for later use
        self.feature_names = list(features_df.columns)
        
        return features_df
    
    def _is_external_ip(self, ip):
        """Check if IP is external (not private range)"""
        if pd.isna(ip) or ip == 'UNKNOWN':
            return False
        
        # Private IP ranges
        private_patterns = [
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
            r'^192\.168\.',
            r'^127\.',
            r'^localhost'
        ]
        
        import re
        for pattern in private_patterns:
            if re.match(pattern, str(ip)):
                return False
        
        return True
    
    def _count_events_in_window(self, df, group_col, minutes=5):
        """Count events from same source in time window"""
        df_sorted = df.sort_values('timestamp').reset_index(drop=True)
        counts = []
        
        for idx, row in df_sorted.iterrows():
            # Get events from same source within time window
            time_mask = (
                (df_sorted['timestamp'] >= row['timestamp'] - pd.Timedelta(minutes=minutes)) &
                (df_sorted['timestamp'] <= row['timestamp']) &
                (df_sorted[group_col] == row[group_col])
            )
            counts.append(time_mask.sum())
        
        return counts
    
    def _count_failed_attempts(self, df):
        """Count cumulative failed attempts by user"""
        df_sorted = df.sort_values('timestamp').reset_index(drop=True)
        failed_counts = []
        user_failures = {}
        
        for idx, row in df_sorted.iterrows():
            user = row['user']
            
            if row['result'] == 'FAILED':
                user_failures[user] = user_failures.get(user, 0) + 1
            elif row['result'] == 'SUCCESS':
                # Reset on success
                user_failures[user] = 0
            
            failed_counts.append(user_failures.get(user, 0))
        
        return failed_counts
    
    def train(self, df):
        """
        Train the anomaly detection model
        
        Args:
            df: Normalized DataFrame with logs
            
        Returns:
            dict: Training results and statistics
        """
        # Extract features
        features = self.extract_features(df)
        
        # Initialize Isolation Forest
        self.model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_state,
            n_estimators=100,
            max_samples='auto',
            verbose=0
        )
        
        # Train model
        self.model.fit(features)
        
        # Get predictions (-1 for anomaly, 1 for normal)
        predictions = self.model.predict(features)
        
        # Get anomaly scores (lower = more anomalous)
        scores = self.model.score_samples(features)
        
        # Normalize scores to 0-1 range (higher = more anomalous)
        normalized_scores = self._normalize_scores(scores)
        
        # Calculate feature importance (pseudo-importance based on variance)
        self.feature_importance = self._calculate_feature_importance(features, predictions)
        
        # Compile results
        results = {
            'total_events': len(df),
            'anomalies_detected': (predictions == -1).sum(),
            'normal_events': (predictions == 1).sum(),
            'anomaly_percentage': (predictions == -1).sum() / len(df) * 100,
            'mean_anomaly_score': normalized_scores.mean(),
            'max_anomaly_score': normalized_scores.max(),
            'feature_importance': self.feature_importance
        }
        
        return results, predictions, normalized_scores
    
    def _normalize_scores(self, scores):
        """Normalize anomaly scores to 0-1 range"""
        # Invert scores (more negative = more anomalous)
        inverted = -scores
        
        # Normalize to 0-1
        min_score = inverted.min()
        max_score = inverted.max()
        
        if max_score - min_score == 0:
            return np.zeros_like(inverted)
        
        normalized = (inverted - min_score) / (max_score - min_score)
        
        return normalized
    
    def _calculate_feature_importance(self, features, predictions):
        """
        Calculate pseudo feature importance based on variance
        Shows which features vary most between normal and anomalous events
        """
        importance = {}
        
        anomaly_mask = predictions == -1
        normal_mask = predictions == 1
        
        for col in features.columns:
            if anomaly_mask.sum() > 0 and normal_mask.sum() > 0:
                # Calculate difference in means
                anomaly_mean = features.loc[anomaly_mask, col].mean()
                normal_mean = features.loc[normal_mask, col].mean()
                
                # Calculate variance difference
                diff = abs(anomaly_mean - normal_mean)
                importance[col] = diff
            else:
                importance[col] = 0
        
        # Normalize importance scores
        total = sum(importance.values())
        if total > 0:
            importance = {k: v/total for k, v in importance.items()}
        
        # Sort by importance
        importance = dict(sorted(importance.items(), key=lambda x: x[1], reverse=True))
        
        return importance
    
    def classify_severity(self, anomaly_score):
        """
        Classify anomaly severity based on score
        
        Args:
            anomaly_score: Score from 0-1
            
        Returns:
            str: Severity level
        """
        if anomaly_score >= 0.8:
            return "CRITICAL"
        elif anomaly_score >= 0.6:
            return "HIGH"
        elif anomaly_score >= 0.4:
            return "MEDIUM"
        elif anomaly_score >= 0.2:
            return "LOW"
        else:
            return "NORMAL"
    
    def get_anomaly_explanation(self, df, idx, features, anomaly_score):
        """
        Generate human-readable explanation for why an event is anomalous
        
        Args:
            df: Original DataFrame
            idx: Index of the event
            features: Feature DataFrame
            anomaly_score: Anomaly score
            
        Returns:
            list: List of reasons
        """
        reasons = []
        event = df.iloc[idx]
        feat = features.iloc[idx]
        
        # Check various anomaly indicators
        if feat['is_external_ip'] == 1:
            reasons.append(f"External IP address: {event['ip_address']}")
        
        if feat['is_high_risk_action'] == 1:
            reasons.append(f"High-risk action: {event['action']}")
        
        if feat['failed_attempts_by_user'] >= 3:
            reasons.append(f"Multiple failed attempts: {feat['failed_attempts_by_user']}")
        
        if feat['is_business_hours'] == 0 and feat['severity_encoded'] >= 2:
            reasons.append("Activity outside business hours")
        
        if feat['is_sensitive_resource'] == 1:
            reasons.append(f"Access to sensitive resource: {event['resource']}")
        
        if feat['user_ip_diversity'] >= 3:
            reasons.append(f"User accessing from multiple IPs")
        
        if feat['events_from_ip_5min'] >= 10:
            reasons.append(f"High activity from IP: {feat['events_from_ip_5min']} events in 5 min")
        
        if event['result'] == 'FAILED' and event['action'] == 'LOGIN':
            reasons.append("Failed login attempt")
        
        if not reasons:
            reasons.append("Statistical anomaly detected by ML model")
        
        return reasons


# Helper function for easy import
def detect_anomalies(df, contamination=0.1):
    """
    Convenience function to detect anomalies in logs
    
    Args:
        df: Normalized DataFrame with logs
        contamination: Expected proportion of anomalies
        
    Returns:
        tuple: (results_dict, anomaly_df)
    """
    detector = AnomalyDetector(contamination=contamination)
    
    # Train and detect
    results, predictions, scores = detector.train(df)
    
    # Create anomaly DataFrame
    anomaly_df = df.copy()
    anomaly_df['is_anomaly'] = (predictions == -1).astype(int)
    anomaly_df['anomaly_score'] = scores
    anomaly_df['severity_level'] = [detector.classify_severity(s) for s in scores]
    
    # Extract features for explanations
    features = detector.extract_features(df)
    
    # Add explanations for anomalies
    explanations = []
    for idx in range(len(df)):
        if predictions[idx] == -1:
            reasons = detector.get_anomaly_explanation(df, idx, features, scores[idx])
            explanations.append("; ".join(reasons))
        else:
            explanations.append("")
    
    anomaly_df['explanation'] = explanations
    
    # Add to results
    results['detector'] = detector
    results['anomaly_dataframe'] = anomaly_df
    
    return results, anomaly_df