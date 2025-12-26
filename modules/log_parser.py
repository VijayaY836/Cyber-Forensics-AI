"""
Log Parser Module
Ingests and normalizes CSV and JSON log files
"""

import pandas as pd
import json
from datetime import datetime
import re

class LogParser:
    """
    Parses and normalizes log files from various formats
    Standardizes fields for downstream analysis
    """
    
    def __init__(self):
        """Initialize the log parser with standard field mappings"""
        # Standard field names we want in the final dataset
        self.standard_fields = [
            'timestamp',
            'user',
            'action',
            'resource',
            'ip_address',
            'result',
            'source',
            'destination',
            'protocol',
            'severity'
        ]
        
        # Field name mappings (handles different naming conventions)
        self.field_mappings = {
            # Timestamp variations
            'time': 'timestamp',
            'datetime': 'timestamp',
            'date': 'timestamp',
            'event_time': 'timestamp',
            'log_time': 'timestamp',
            
            # User variations
            'username': 'user',
            'user_name': 'user',
            'userid': 'user',
            'account': 'user',
            
            # Action variations
            'event': 'action',
            'event_type': 'action',
            'activity': 'action',
            'operation': 'action',
            
            # Resource variations
            'file': 'resource',
            'path': 'resource',
            'object': 'resource',
            'target': 'resource',
            
            # IP variations
            'ip': 'ip_address',
            'source_ip': 'ip_address',
            'src_ip': 'ip_address',
            'client_ip': 'ip_address',
            
            # Result variations
            'status': 'result',
            'outcome': 'result',
            'response': 'result',
            
            # Source variations
            'src': 'source',
            'source_host': 'source',
            
            # Destination variations
            'dest': 'destination',
            'dst': 'destination',
            'destination_host': 'destination',
            
            # Protocol variations
            'proto': 'protocol',
            'service': 'protocol',
            
            # Severity variations
            'level': 'severity',
            'priority': 'severity',
            'alert_level': 'severity'
        }
    
    def parse_csv(self, file_path_or_buffer):
        """
        Parse CSV log file
        
        Args:
            file_path_or_buffer: File path string or file buffer
            
        Returns:
            pd.DataFrame: Normalized log data
        """
        try:
            # Read CSV file
            df = pd.read_csv(file_path_or_buffer)
            
            # Normalize the dataframe
            df_normalized = self._normalize_dataframe(df)
            
            return df_normalized
            
        except Exception as e:
            raise Exception(f"Error parsing CSV: {str(e)}")
    
    def parse_json(self, file_path_or_buffer):
        """
        Parse JSON log file
        
        Args:
            file_path_or_buffer: File path string or file buffer
            
        Returns:
            pd.DataFrame: Normalized log data
        """
        try:
            # Read JSON file
            df = pd.read_json(file_path_or_buffer)
            
            # Normalize the dataframe
            df_normalized = self._normalize_dataframe(df)
            
            return df_normalized
            
        except Exception as e:
            raise Exception(f"Error parsing JSON: {str(e)}")
    
    def _normalize_dataframe(self, df):
        """
        Normalize dataframe column names and add missing fields
        
        Args:
            df: Raw pandas DataFrame
            
        Returns:
            pd.DataFrame: Normalized DataFrame
        """
        # Create a copy to avoid modifying original
        df_norm = df.copy()
        
        # Convert all column names to lowercase for consistency
        df_norm.columns = df_norm.columns.str.lower().str.strip()
        
        # Apply field mappings
        df_norm = df_norm.rename(columns=self.field_mappings)
        
        # Parse timestamps if present
        if 'timestamp' in df_norm.columns:
            df_norm['timestamp'] = self._parse_timestamps(df_norm['timestamp'])
        else:
            # If no timestamp, use current time with incremental seconds
            df_norm['timestamp'] = pd.date_range(
                start=datetime.now(),
                periods=len(df_norm),
                freq='S'
            )
        
        # Add missing standard fields with default values
        for field in self.standard_fields:
            if field not in df_norm.columns:
                df_norm[field] = 'UNKNOWN'
        
        # Ensure result field has consistent values
        if 'result' in df_norm.columns:
            df_norm['result'] = df_norm['result'].apply(self._standardize_result)
        
        # Add event_id for tracking
        df_norm['event_id'] = [f"EVT_{i:06d}" for i in range(len(df_norm))]
        
        # Sort by timestamp
        df_norm = df_norm.sort_values('timestamp').reset_index(drop=True)
        
        # Reorder columns to put standard fields first
        column_order = ['event_id'] + self.standard_fields
        other_columns = [col for col in df_norm.columns if col not in column_order]
        df_norm = df_norm[column_order + other_columns]
        
        return df_norm
    
    def _parse_timestamps(self, timestamp_series):
        """
        Parse timestamps from various formats
        
        Args:
            timestamp_series: Pandas Series containing timestamps
            
        Returns:
            pd.Series: Parsed datetime objects
        """
        try:
            # Try pandas automatic parsing first
            parsed = pd.to_datetime(timestamp_series, errors='coerce')
            
            # If any failed to parse, try common formats manually
            if parsed.isna().any():
                for format_str in [
                    '%Y-%m-%d %H:%M:%S',
                    '%Y-%m-%dT%H:%M:%S',
                    '%d/%m/%Y %H:%M:%S',
                    '%m/%d/%Y %H:%M:%S',
                    '%Y/%m/%d %H:%M:%S',
                    '%Y-%m-%d %H:%M:%S.%f',
                    '%d-%m-%Y %H:%M:%S'
                ]:
                    try:
                        parsed = pd.to_datetime(timestamp_series, format=format_str, errors='coerce')
                        if not parsed.isna().any():
                            break
                    except:
                        continue
            
            return parsed
            
        except Exception as e:
            # If all parsing fails, return current time
            return pd.Series([datetime.now()] * len(timestamp_series))
    
    def _standardize_result(self, result):
        """
        Standardize result/status values
        
        Args:
            result: Raw result value
            
        Returns:
            str: Standardized result (SUCCESS, FAILED, ERROR, UNKNOWN)
        """
        if pd.isna(result) or result == 'UNKNOWN':
            return 'UNKNOWN'
        
        result_str = str(result).upper()
        
        # Success patterns
        if any(word in result_str for word in ['SUCCESS', 'OK', 'ALLOWED', 'ACCEPT', 'GRANTED', '200', 'PASS']):
            return 'SUCCESS'
        
        # Failed patterns
        if any(word in result_str for word in ['FAIL', 'DENIED', 'REJECT', 'BLOCKED', '401', '403', '404']):
            return 'FAILED'
        
        # Error patterns
        if any(word in result_str for word in ['ERROR', '500', '502', '503']):
            return 'ERROR'
        
        return 'UNKNOWN'
    
    def get_statistics(self, df):
        """
        Generate statistics about the parsed logs
        
        Args:
            df: Normalized DataFrame
            
        Returns:
            dict: Statistics dictionary
        """
        stats = {
            'total_events': len(df),
            'date_range': {
                'start': df['timestamp'].min(),
                'end': df['timestamp'].max()
            },
            'unique_users': df['user'].nunique(),
            'unique_ips': df['ip_address'].nunique(),
            'result_distribution': df['result'].value_counts().to_dict(),
            'action_distribution': df['action'].value_counts().head(10).to_dict(),
            'fields_present': list(df.columns),
            'missing_data_percentage': (df == 'UNKNOWN').sum().sum() / (len(df) * len(df.columns)) * 100
        }
        
        return stats
    
    def validate_logs(self, df):
        """
        Validate parsed logs for quality issues
        
        Args:
            df: Normalized DataFrame
            
        Returns:
            dict: Validation results with warnings
        """
        warnings = []
        
        # Check for missing timestamps
        if df['timestamp'].isna().any():
            warnings.append(f"⚠️ {df['timestamp'].isna().sum()} events have invalid timestamps")
        
        # Check for too many unknowns
        unknown_percentage = (df == 'UNKNOWN').sum().sum() / (len(df) * len(df.columns)) * 100
        if unknown_percentage > 30:
            warnings.append(f"⚠️ {unknown_percentage:.1f}% of data is UNKNOWN - log format may not be standard")
        
        # Check for duplicate events
        if df.duplicated().any():
            warnings.append(f"⚠️ {df.duplicated().sum()} duplicate events detected")
        
        # Check for suspicious patterns
        if len(df) < 10:
            warnings.append("⚠️ Very few events - analysis may not be reliable")
        
        return {
            'is_valid': len(warnings) == 0,
            'warnings': warnings
        }


# Helper function for easy import
def parse_logs(file_buffer, file_type='csv'):
    """
    Convenience function to parse logs
    
    Args:
        file_buffer: File buffer from Streamlit uploader
        file_type: 'csv' or 'json'
        
    Returns:
        tuple: (DataFrame, statistics, validation_results)
    """
    parser = LogParser()
    
    if file_type == 'csv':
        df = parser.parse_csv(file_buffer)
    elif file_type == 'json':
        df = parser.parse_json(file_buffer)
    else:
        raise ValueError(f"Unsupported file type: {file_type}")
    
    stats = parser.get_statistics(df)
    validation = parser.validate_logs(df)
    
    return df, stats, validation