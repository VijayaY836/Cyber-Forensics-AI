"""
AI-Based Log Investigation Framework for Next-Generation Cyber Forensics
Main Streamlit Dashboard Application
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import json

# Page configuration
st.set_page_config(
    page_title="Cyber Forensics AI",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load custom CSS
def load_css():
    """Load custom dark theme CSS"""
    try:
        with open("assets/style.css") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)
    except FileNotFoundError:
        st.warning("Custom CSS file not found. Using default theme.")

load_css()

# Initialize session state
if 'logs_data' not in st.session_state:
    st.session_state.logs_data = None
if 'analysis_complete' not in st.session_state:
    st.session_state.analysis_complete = False
if 'anomalies' not in st.session_state:
    st.session_state.anomalies = None
if 'attack_chains' not in st.session_state:
    st.session_state.attack_chains = None

# ============================================================================
# SIDEBAR NAVIGATION
# ============================================================================

st.sidebar.title("🔍 Cyber Forensics AI")
st.sidebar.markdown("---")
st.sidebar.markdown("### 🎯 Navigation")

# Navigation menu
page = st.sidebar.radio(
    "Select Analysis Module:",
    [
        "🏠 Home",
        "📤 Upload Logs",
        "🔎 Anomaly Detection",
        "🔗 Event Correlation",
        "⏱️ Timeline Analysis",
        "📊 Forensic Report"
    ]
)

st.sidebar.markdown("---")
st.sidebar.markdown("### 📊 System Status")

# Status metrics in sidebar
if st.session_state.logs_data is not None:
    st.sidebar.success("✅ Logs Loaded")
    st.sidebar.metric("Total Events", len(st.session_state.logs_data))
else:
    st.sidebar.info("⏳ No Logs Loaded")

if st.session_state.analysis_complete:
    st.sidebar.success("✅ Analysis Complete")
else:
    st.sidebar.warning("⏳ Awaiting Analysis")

st.sidebar.markdown("---")
st.sidebar.markdown("### ℹ️ About")
st.sidebar.info(
    """
    **Version:** 1.0.0  
    **Tech Stack:**  
    • Python + Streamlit  
    • scikit-learn  
    • NetworkX  
    • Plotly  
    
    **Created for:**  
    Cyber Security Hackathon 2025
    """
)

# ============================================================================
# PAGE: HOME
# ============================================================================

if page == "🏠 Home":
    st.title("🔍 AI-Based Log Investigation Framework")
    st.markdown("### *Next-Generation Cyber Forensics with Machine Learning*")
    st.markdown("---")
    
    # Hero section with key metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="📊 Total Events",
            value="0" if st.session_state.logs_data is None else len(st.session_state.logs_data),
            delta="Ready to analyze"
        )
    
    with col2:
        st.metric(
            label="⚠️ Anomalies",
            value="0" if st.session_state.anomalies is None else len(st.session_state.anomalies),
            delta="Pending detection"
        )
    
    with col3:
        st.metric(
            label="🔗 Attack Chains",
            value="0" if st.session_state.attack_chains is None else len(st.session_state.attack_chains),
            delta="Pending correlation"
        )
    
    with col4:
        st.metric(
            label="🎯 Confidence",
            value="N/A" if not st.session_state.analysis_complete else "87%",
            delta="ML-powered"
        )
    
    st.markdown("---")
    
    # Feature showcase
    st.markdown("## 🚀 Key Features")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        ### 🤖 AI-Powered Detection
        - **Isolation Forest** algorithm for anomaly detection
        - Unsupervised learning on log patterns
        - Real-time threat scoring
        
        ### 🔗 Event Correlation
        - Graph-based attack chain reconstruction
        - Multi-stage attack identification
        - Behavioral pattern analysis
        """)
    
    with col2:
        st.markdown("""
        ### ⏱️ Timeline Reconstruction
        - Chronological event sequencing
        - Attack phase highlighting
        - Visual forensic timeline
        
        ### 📊 Explainable Reports
        - Auto-generated forensic analysis
        - Evidence-based conclusions
        - Confidence scoring
        """)
    
    st.markdown("---")
    
    # Placeholder visualization
    st.markdown("## 📈 System Overview")
    
    # Create sample data for demo chart
    demo_data = pd.DataFrame({
        'Time': pd.date_range(start='2024-12-26 00:00', periods=24, freq='H'),
        'Normal Events': [50, 48, 52, 55, 60, 58, 62, 70, 75, 80, 85, 90, 88, 92, 95, 90, 85, 80, 75, 70, 65, 60, 55, 50],
        'Suspicious Events': [2, 3, 1, 2, 3, 5, 8, 12, 15, 10, 8, 5, 3, 2, 4, 6, 8, 10, 12, 8, 5, 3, 2, 1]
    })
    
    fig = px.line(
        demo_data, 
        x='Time', 
        y=['Normal Events', 'Suspicious Events'],
        title='Event Distribution Over Time (Demo Data)',
        labels={'value': 'Event Count', 'variable': 'Event Type'}
    )
    fig.update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#fafafa'),
        title_font=dict(color='#00ff41', size=20)
    )
    st.plotly_chart(fig, use_container_width=True)
    
    st.info("💡 **Get Started:** Upload your log files using the '📤 Upload Logs' section in the sidebar!")

# ============================================================================
# PAGE: UPLOAD LOGS
# ============================================================================

elif page == "📤 Upload Logs":
    st.title("📤 Log Upload & Ingestion")
    st.markdown("### Upload your system or security logs for analysis")
    st.markdown("---")
    
    # Import parser
    from modules.log_parser import parse_logs
    
    # File upload section
    st.markdown("## 📁 Supported Formats")
    col1, col2 = st.columns(2)
    
    with col1:
        st.info("**CSV Files**\n\nComma-separated log files with headers")
    
    with col2:
        st.info("**JSON Files**\n\nStructured JSON log arrays")
    
    st.markdown("---")
    
    # File uploader
    uploaded_file = st.file_uploader(
        "Choose a log file",
        type=['csv', 'json'],
        help="Upload CSV or JSON log files for forensic analysis"
    )
    
    if uploaded_file is not None:
        st.success(f"✅ File uploaded: **{uploaded_file.name}**")
        
        # Display file details
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("File Name", uploaded_file.name)
        with col2:
            st.metric("File Type", uploaded_file.type)
        with col3:
            st.metric("File Size", f"{uploaded_file.size / 1024:.2f} KB")
        
        st.markdown("---")
        
        # Parse button
        if st.button("🔍 Parse & Normalize Logs", type="primary"):
            with st.spinner("🔄 Parsing and normalizing log file..."):
                try:
                    # Determine file type
                    file_type = 'csv' if uploaded_file.name.endswith('.csv') else 'json'
                    
                    # Parse logs using our module
                    df, stats, validation = parse_logs(uploaded_file, file_type)
                    
                    # Store in session state
                    st.session_state.logs_data = df
                    st.session_state.log_stats = stats
                    st.session_state.log_validation = validation
                    
                    st.success(f"✅ Successfully parsed and normalized **{len(df)}** log entries!")
                    
                    # Display validation warnings
                    if not validation['is_valid']:
                        with st.expander("⚠️ Validation Warnings", expanded=True):
                            for warning in validation['warnings']:
                                st.warning(warning)
                    else:
                        st.info("✅ All validation checks passed!")
                    
                    st.markdown("---")
                    
                    # Display statistics
                    st.markdown("### 📊 Log Statistics")
                    
                    col1, col2, col3, col4 = st.columns(4)
                    
                    with col1:
                        st.metric("Total Events", stats['total_events'])
                    
                    with col2:
                        st.metric("Unique Users", stats['unique_users'])
                    
                    with col3:
                        st.metric("Unique IPs", stats['unique_ips'])
                    
                    with col4:
                        missing_pct = stats['missing_data_percentage']
                        st.metric("Data Quality", f"{100-missing_pct:.1f}%")
                    
                    # Date range
                    st.markdown("#### 📅 Time Range")
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write("**Start:**", stats['date_range']['start'])
                    with col2:
                        st.write("**End:**", stats['date_range']['end'])
                    
                    st.markdown("---")
                    
                    # Result distribution
                    st.markdown("#### 📈 Result Distribution")
                    result_df = pd.DataFrame({
                        'Result': list(stats['result_distribution'].keys()),
                        'Count': list(stats['result_distribution'].values())
                    })
                    
                    fig = px.bar(
                        result_df,
                        x='Result',
                        y='Count',
                        title='Event Results Overview',
                        color='Result',
                        color_discrete_map={
                            'SUCCESS': '#00ff41',
                            'FAILED': '#ff4136',
                            'ERROR': '#ff851b',
                            'UNKNOWN': '#7fdbff'
                        }
                    )
                    fig.update_layout(
                        plot_bgcolor='rgba(0,0,0,0)',
                        paper_bgcolor='rgba(0,0,0,0)',
                        font=dict(color='#fafafa')
                    )
                    st.plotly_chart(fig, use_container_width=True)
                    
                    st.markdown("---")
                    
                    # Display normalized preview
                    st.markdown("### 📋 Normalized Log Preview (First 20 entries)")
                    st.dataframe(df.head(20), use_container_width=True)
                    
                    # Display column info
                    st.markdown("### 🔍 Data Schema")
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write("**Normalized Fields:**")
                        st.write(stats['fields_present'][:10])
                    
                    with col2:
                        st.write("**Shape:**", df.shape)
                        st.write("**Memory Usage:**", f"{df.memory_usage(deep=True).sum() / 1024:.2f} KB")
                    
                    # Top actions
                    st.markdown("#### 🎯 Top 10 Actions")
                    action_df = pd.DataFrame({
                        'Action': list(stats['action_distribution'].keys()),
                        'Count': list(stats['action_distribution'].values())
                    })
                    st.dataframe(action_df, use_container_width=True)
                    
                except Exception as e:
                    st.error(f"❌ Error parsing file: {str(e)}")
                    st.exception(e)
    
    else:
        st.info("👆 Please upload a log file to begin analysis")
        
        # Show sample data structure
        st.markdown("---")
        st.markdown("## 📝 Expected Log Format")
        
        st.markdown("**The parser automatically handles various field names. Here are examples:**")
        
        sample_data = pd.DataFrame({
            'timestamp': ['2024-12-26 10:15:30', '2024-12-26 10:16:45'],
            'user': ['admin', 'john_doe'],
            'action': ['LOGIN', 'FILE_ACCESS'],
            'resource': ['/admin/panel', '/data/sensitive.xlsx'],
            'ip_address': ['192.168.1.100', '10.0.0.50'],
            'result': ['SUCCESS', 'FAILED']
        })
        
        st.dataframe(sample_data, use_container_width=True)
        st.caption("✅ CSV or JSON format supported | Field names auto-normalized")

# ============================================================================
# PAGE: ANOMALY DETECTION
# ============================================================================

elif page == "🔎 Anomaly Detection":
    st.title("🔎 Anomaly Detection")
    st.markdown("### Machine Learning-based anomaly identification")
    st.markdown("---")
    
    if st.session_state.logs_data is None:
        st.warning("⚠️ No logs loaded. Please upload logs first!")
        st.info("👉 Go to '📤 Upload Logs' to get started")
    else:
        from modules.anomaly_detector import detect_anomalies
        
        st.success(f"✅ Analyzing **{len(st.session_state.logs_data)}** log entries")
        
        # Anomaly detection controls
        col1, col2 = st.columns([3, 1])
        
        with col1:
            contamination = st.slider(
                "Contamination Factor (Expected % of anomalies)",
                min_value=0.01,
                max_value=0.5,
                value=0.1,
                step=0.01,
                help="Proportion of outliers in the dataset"
            )
        
        with col2:
            run_detection = st.button("🚀 Run Detection", type="primary")
        
        # Run detection
        if run_detection or st.session_state.anomalies is not None:
            if run_detection:
                with st.spinner("🧠 Running ML-based anomaly detection..."):
                    try:
                        # Run detection
                        results, anomaly_df = detect_anomalies(
                            st.session_state.logs_data, 
                            contamination=contamination
                        )
                        
                        # Store in session state
                        st.session_state.anomalies = anomaly_df
                        st.session_state.anomaly_results = results
                        st.session_state.analysis_complete = True
                        
                        st.success("✅ Anomaly detection complete!")
                        
                    except Exception as e:
                        st.error(f"❌ Error during detection: {str(e)}")
                        st.exception(e)
            
            # Display results
            if st.session_state.anomalies is not None:
                results = st.session_state.anomaly_results
                anomaly_df = st.session_state.anomalies
                
                st.markdown("---")
                st.markdown("## 📊 Detection Results")
                
                # Metrics
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric(
                        "Normal Events", 
                        results['normal_events'],
                        delta=f"{100-results['anomaly_percentage']:.1f}%"
                    )
                
                with col2:
                    st.metric(
                        "Anomalies Detected", 
                        results['anomalies_detected'],
                        delta=f"{results['anomaly_percentage']:.1f}%",
                        delta_color="inverse"
                    )
                
                with col3:
                    critical_count = (anomaly_df['severity_level'] == 'CRITICAL').sum()
                    st.metric(
                        "Critical Severity", 
                        critical_count,
                        delta="Urgent" if critical_count > 0 else "None"
                    )
                
                with col4:
                    st.metric(
                        "Max Anomaly Score",
                        f"{results['max_anomaly_score']:.2f}",
                        delta="0.0 - 1.0 scale"
                    )
                
                st.markdown("---")
                
                # Anomaly score distribution
                st.markdown("### 🎯 Anomaly Score Distribution")
                
                fig = go.Figure()
                
                # Separate normal and anomalous
                normal_scores = anomaly_df[anomaly_df['is_anomaly'] == 0]['anomaly_score']
                anomaly_scores = anomaly_df[anomaly_df['is_anomaly'] == 1]['anomaly_score']
                
                fig.add_trace(go.Histogram(
                    x=normal_scores,
                    nbinsx=30,
                    name='Normal Events',
                    marker_color='#00ff41',
                    opacity=0.7
                ))
                
                fig.add_trace(go.Histogram(
                    x=anomaly_scores,
                    nbinsx=30,
                    name='Anomalies',
                    marker_color='#ff4136',
                    opacity=0.7
                ))
                
                fig.update_layout(
                    title='Anomaly Score Distribution',
                    xaxis_title='Anomaly Score (0 = Normal, 1 = Highly Anomalous)',
                    yaxis_title='Frequency',
                    barmode='overlay',
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    font=dict(color='#fafafa'),
                    showlegend=True
                )
                
                st.plotly_chart(fig, use_container_width=True)
                
                st.markdown("---")
                
                # Severity distribution
                st.markdown("### 🚨 Severity Distribution")
                
                severity_counts = anomaly_df['severity_level'].value_counts()
                
                fig2 = px.pie(
                    values=severity_counts.values,
                    names=severity_counts.index,
                    title='Event Severity Levels',
                    color=severity_counts.index,
                    color_discrete_map={
                        'NORMAL': '#00ff41',
                        'LOW': '#7fdbff',
                        'MEDIUM': '#ffdc00',
                        'HIGH': '#ff851b',
                        'CRITICAL': '#ff4136'
                    }
                )
                
                fig2.update_layout(
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    font=dict(color='#fafafa')
                )
                
                st.plotly_chart(fig2, use_container_width=True)
                
                st.markdown("---")
                
                # Feature importance
                st.markdown("### 🔍 Feature Importance")
                st.info("Shows which features contribute most to anomaly detection")
                
                importance = results['feature_importance']
                top_features = dict(list(importance.items())[:10])
                
                fig3 = px.bar(
                    x=list(top_features.values()),
                    y=list(top_features.keys()),
                    orientation='h',
                    title='Top 10 Most Important Features',
                    labels={'x': 'Importance Score', 'y': 'Feature'},
                    color=list(top_features.values()),
                    color_continuous_scale='Greens'
                )
                
                fig3.update_layout(
                    plot_bgcolor='rgba(0,0,0,0)',
                    paper_bgcolor='rgba(0,0,0,0)',
                    font=dict(color='#fafafa'),
                    showlegend=False
                )
                
                st.plotly_chart(fig3, use_container_width=True)
                
                st.markdown("---")
                
                # Detected anomalies table
                st.markdown("### ⚠️ Detected Anomalies")
                
                anomalies_only = anomaly_df[anomaly_df['is_anomaly'] == 1].sort_values(
                    'anomaly_score', 
                    ascending=False
                )
                
                if len(anomalies_only) > 0:
                    st.write(f"**Showing {len(anomalies_only)} anomalous events:**")
                    
                    # Display table with key columns
                    display_cols = [
                        'event_id', 'timestamp', 'user', 'action', 
                        'ip_address', 'result', 'anomaly_score', 
                        'severity_level', 'explanation'
                    ]
                    
                    st.dataframe(
                        anomalies_only[display_cols].head(20),
                        use_container_width=True
                    )
                    
                    # Download button
                    csv = anomalies_only.to_csv(index=False)
                    st.download_button(
                        label="📥 Download Anomalies as CSV",
                        data=csv,
                        file_name="detected_anomalies.csv",
                        mime="text/csv"
                    )
                else:
                    st.info("✅ No anomalies detected in the dataset!")
        
        else:
            st.info("👆 Click 'Run Detection' to start ML analysis")

# ============================================================================
# PAGE: EVENT CORRELATION
# ============================================================================

elif page == "🔗 Event Correlation":
    st.title("🔗 Event Correlation & Attack Chains")
    st.markdown("### Graph-based correlation of related events")
    st.markdown("---")
    
    if st.session_state.logs_data is None:
        st.warning("⚠️ No logs loaded. Please upload logs first!")
    elif st.session_state.anomalies is None:
        st.warning("⚠️ Please run anomaly detection first!")
        st.info("👉 Go to '🔎 Anomaly Detection' and click 'Run Detection'")
    else:
        from modules.event_correlator import correlate_events
        from utils.visualization import create_attack_chain_graph, create_timeline_chart
        
        st.success("✅ Ready for event correlation")
        
        # Correlation controls
        col1, col2 = st.columns([3, 1])
        
        with col1:
            time_window = st.slider(
                "Time Window (minutes)",
                min_value=5,
                max_value=120,
                value=30,
                step=5,
                help="Maximum time gap between related events"
            )
        
        with col2:
            run_correlation = st.button("🔗 Build Attack Chains", type="primary")
        
        # Run correlation
        if run_correlation or st.session_state.attack_chains is not None:
            if run_correlation:
                with st.spinner("🔗 Correlating events and building attack chains..."):
                    try:
                        # Run correlation
                        results, chains = correlate_events(
                            st.session_state.logs_data,
                            st.session_state.anomalies,
                            time_window=time_window
                        )
                        
                        # Store in session state
                        st.session_state.attack_chains = chains
                        st.session_state.correlation_results = results
                        
                        st.success("✅ Event correlation complete!")
                        
                    except Exception as e:
                        st.error(f"❌ Error during correlation: {str(e)}")
                        st.exception(e)
            
            # Display results
            if st.session_state.attack_chains is not None:
                results = st.session_state.correlation_results
                chains = st.session_state.attack_chains
                
                st.markdown("---")
                st.markdown("## 📊 Correlation Results")
                
                # Metrics
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric(
                        "Attack Chains",
                        results['attack_chains_detected'],
                        delta="Multi-stage"
                    )
                
                with col2:
                    st.metric(
                        "Correlated Events",
                        results['correlated_events'],
                        delta=f"{results['correlated_events']/results['total_events']*100:.1f}%"
                    )
                
                with col3:
                    st.metric(
                        "Unique Attackers",
                        results['unique_attackers'],
                        delta="IP addresses"
                    )
                
                with col4:
                    critical_chains = sum(1 for c in chains if c['severity'] == 'CRITICAL')
                    st.metric(
                        "Critical Chains",
                        critical_chains,
                        delta="Urgent" if critical_chains > 0 else "None"
                    )
                
                st.markdown("---")
                
                # Attack chain graph visualization
                if len(chains) > 0:
                    st.markdown("### 🕸️ Attack Correlation Graph")
                    st.info("Interactive graph showing relationships between correlated events")
                    
                    graph = results['graph']
                    fig_graph = create_attack_chain_graph(graph)
                    st.plotly_chart(fig_graph, use_container_width=True)
                    
                    st.markdown("---")
                    
                    # Attack chains summary
                    st.markdown("### 🎯 Detected Attack Chains")
                    
                    for idx, chain in enumerate(chains):
                        # Color based on severity
                        severity_colors = {
                            'CRITICAL': '🔴',
                            'HIGH': '🟠',
                            'MEDIUM': '🟡',
                            'LOW': '🟢'
                        }
                        
                        severity_icon = severity_colors.get(chain['severity'], '⚪')
                        
                        with st.expander(
                            f"{severity_icon} **{chain['chain_id']}** - {chain['pattern']} "
                            f"({chain['event_count']} events, {chain['severity']} severity)",
                            expanded=(idx == 0)  # Expand first chain by default
                        ):
                            # Chain details
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                st.markdown("**Chain Information:**")
                                st.write(f"• **Pattern:** {chain['pattern']}")
                                st.write(f"• **Severity:** {chain['severity']}")
                                st.write(f"• **Events:** {chain['event_count']}")
                                st.write(f"• **Duration:** {chain['duration']:.0f} seconds")
                                st.write(f"• **Max Anomaly Score:** {chain['max_anomaly_score']:.2f}")
                            
                            with col2:
                                st.markdown("**Attack Details:**")
                                st.write(f"• **Primary IP:** {chain['primary_ip']}")
                                st.write(f"• **Users Involved:** {', '.join(chain['users']) if chain['users'] else 'Unknown'}")
                                st.write(f"• **Start Time:** {chain['start_time']}")
                                st.write(f"• **End Time:** {chain['end_time']}")
                            
                            st.markdown("---")
                            
                            # Event sequence table
                            st.markdown("**Event Sequence:**")
                            
                            chain_df = pd.DataFrame(chain['events'])
                            display_cols = [
                                'timestamp', 'user', 'action', 'resource',
                                'ip_address', 'result', 'anomaly_score'
                            ]
                            
                            # Add sequence numbers
                            chain_df['#'] = range(1, len(chain_df) + 1)
                            display_cols = ['#'] + display_cols
                            
                            st.dataframe(
                                chain_df[display_cols],
                                use_container_width=True,
                                hide_index=True
                            )
                            
                            # Timeline visualization
                            st.markdown("**Timeline Visualization:**")
                            fig_timeline = create_timeline_chart(chain)
                            st.plotly_chart(fig_timeline, use_container_width=True)
                    
                    st.markdown("---")
                    
                    # Attack pattern summary
                    st.markdown("### 📋 Attack Pattern Summary")
                    
                    pattern_counts = {}
                    for chain in chains:
                        pattern = chain['pattern']
                        pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1
                    
                    pattern_df = pd.DataFrame({
                        'Attack Pattern': list(pattern_counts.keys()),
                        'Occurrences': list(pattern_counts.values())
                    }).sort_values('Occurrences', ascending=False)
                    
                    fig_patterns = px.bar(
                        pattern_df,
                        x='Occurrences',
                        y='Attack Pattern',
                        orientation='h',
                        title='Attack Pattern Distribution',
                        color='Occurrences',
                        color_continuous_scale='Reds'
                    )
                    
                    fig_patterns.update_layout(
                        plot_bgcolor='rgba(0,0,0,0)',
                        paper_bgcolor='rgba(0,0,0,0)',
                        font=dict(color='#fafafa')
                    )
                    
                    st.plotly_chart(fig_patterns, use_container_width=True)
                    
                else:
                    st.info("✅ No attack chains detected - all events appear isolated")
        
        else:
            st.info("👆 Click 'Build Attack Chains' to start correlation analysis")

# ============================================================================
# PAGE: TIMELINE ANALYSIS
# ============================================================================

elif page == "⏱️ Timeline Analysis":
    st.title("⏱️ Attack Timeline Reconstruction")
    st.markdown("### Chronological sequence of events with kill chain mapping")
    st.markdown("---")
    
    if st.session_state.logs_data is None:
        st.warning("⚠️ No logs loaded. Please upload logs first!")
    elif st.session_state.anomalies is None:
        st.warning("⚠️ Please run anomaly detection first!")
        st.info("👉 Go to '🔎 Anomaly Detection' and click 'Run Detection'")
    else:
        from modules.timeline_builder import build_timeline
        from utils.visualization import (
            create_gantt_timeline, 
            create_phase_distribution_chart,
            create_temporal_heatmap
        )
        
        st.success("✅ Timeline analysis ready")
        
        # Single button for timeline reconstruction
        reconstruct_clicked = st.button("⏱️ Reconstruct Timeline", type="primary", key="timeline_btn")
        if reconstruct_clicked or 'timeline_results' in st.session_state:
            if reconstruct_clicked or 'timeline_results' not in st.session_state:
                with st.spinner("⏱️ Building chronological timeline..."):
                    try:
                        timeline_results = build_timeline(
                            st.session_state.logs_data,
                            st.session_state.anomalies,
                            st.session_state.attack_chains if 'attack_chains' in st.session_state else None
                        )
                        st.session_state.timeline_results = timeline_results
                        st.success("✅ Timeline reconstruction complete!")
                    except Exception as e:
                        st.error(f"❌ Error during timeline reconstruction: {str(e)}")
                        st.exception(e)
            # Display results
            if 'timeline_results' in st.session_state:
                results = st.session_state.timeline_results
                stats = results['stats']
                timeline_df = results['timeline_df']
                
                st.markdown("---")
                st.markdown("## 📊 Timeline Overview")
                
                # Metrics
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    st.metric(
                        "Total Events",
                        stats['total_events']
                    )
                
                with col2:
                    duration_hours = stats['time_span'].total_seconds() / 3600
                    st.metric(
                        "Duration",
                        f"{duration_hours:.1f}h" if duration_hours >= 1 else f"{stats['time_span'].total_seconds()/60:.0f}m"
                    )
                
                with col3:
                    st.metric(
                        "Kill Chain Phases",
                        stats['phases_observed']
                    )
                
                with col4:
                    st.metric(
                        "High-Risk Events",
                        stats['high_risk_phases'],
                        delta="Critical" if stats['high_risk_phases'] > 0 else "None"
                    )
                
                # Time range
                col1, col2 = st.columns(2)
                with col1:
                    st.info(f"**Start:** {stats['start_time']}")
                with col2:
                    st.info(f"**End:** {stats['end_time']}")
                
                st.markdown("---")
                
                # Attack narrative
                st.markdown("## 📖 Attack Narrative")
                with st.expander("View AI-Generated Attack Story", expanded=True):
                    st.markdown(results['narrative'])
                
                st.markdown("---")
                
                # Gantt timeline visualization
                st.markdown("## 📅 Interactive Timeline")
                st.info("Events colored by anomaly severity | Click and drag to zoom")
                
                fig_gantt = create_gantt_timeline(results['timeline_events'])
                st.plotly_chart(fig_gantt, use_container_width=True)
                
                st.markdown("---")
                
                # Kill chain phase analysis
                st.markdown("## 🎯 Kill Chain Phase Analysis")
                
                col1, col2 = st.columns([1, 1])
                
                with col1:
                    st.markdown("### Phase Distribution")
                    fig_phases = create_phase_distribution_chart(results['phase_distribution'])
                    st.plotly_chart(fig_phases, use_container_width=True)
                
                with col2:
                    st.markdown("### Phase Summary")
                    st.markdown(results['phase_summary'])
                
                st.markdown("---")
                
                # Temporal heatmap
                st.markdown("## 🔥 Temporal Activity Heatmap")
                st.info("Shows when attacks occurred - darker = more activity")
                
                fig_heatmap = create_temporal_heatmap(timeline_df)
                st.plotly_chart(fig_heatmap, use_container_width=True)
                
                st.markdown("---")
                
                # Critical periods
                if results['critical_periods']:
                    st.markdown("## ⚠️ Critical Time Periods")
                    st.write(f"**{len(results['critical_periods'])} high-activity periods detected:**")
                    
                    for period in results['critical_periods'][:10]:  # Show top 10
                        severity_color = '🔴' if period['severity'] == 'CRITICAL' else '🟠'
                        st.warning(
                            f"{severity_color} **{period['start']}** to **{period['end']}** | "
                            f"{period['event_count']} events | "
                            f"Avg Anomaly: {period['avg_anomaly']:.2f}"
                        )
                
                st.markdown("---")
                
                # Detailed timeline table
                st.markdown("## 📋 Detailed Event Timeline")
                
                # Filter options
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    phase_filter = st.multiselect(
                        "Filter by Phase:",
                        options=timeline_df['kill_chain_phase'].unique().tolist(),
                        default=[]
                    )
                
                with col2:
                    severity_filter = st.multiselect(
                        "Filter by Severity:",
                        options=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NORMAL'],
                        default=[]
                    )
                
                with col3:
                    show_anomalies_only = st.checkbox("Show Anomalies Only")
                
                # Apply filters
                filtered_df = timeline_df.copy()
                
                if phase_filter:
                    filtered_df = filtered_df[filtered_df['kill_chain_phase'].isin(phase_filter)]
                
                if severity_filter:
                    filtered_df = filtered_df[filtered_df['severity_level'].isin(severity_filter)]
                
                if show_anomalies_only:
                    filtered_df = filtered_df[filtered_df['anomaly_score'] > 0.6]
                
                # Display table
                display_cols = [
                    'sequence', 'timestamp', 'kill_chain_phase', 'action',
                    'user', 'ip_address', 'resource', 'result',
                    'anomaly_score', 'severity_level'
                ]
                
                st.dataframe(
                    filtered_df[display_cols],
                    use_container_width=True,
                    height=400
                )
                
                # Download button
                csv = filtered_df.to_csv(index=False)
                st.download_button(
                    label="📥 Download Timeline as CSV",
                    data=csv,
                    file_name="attack_timeline.csv",
                    mime="text/csv"
                )
        
        else:
            st.info("👆 Click 'Reconstruct Timeline' to analyze event sequence")

# ============================================================================
# PAGE: FORENSIC REPORT
# ============================================================================

elif page == "📊 Forensic Report":
    st.title("📊 Forensic Analysis Report")
    st.markdown("### Auto-generated explainable forensic investigation report")
    st.markdown("---")
    
    if st.session_state.logs_data is None:
        st.warning("⚠️ No logs loaded. Please upload logs first!")
    elif st.session_state.anomalies is None:
        st.warning("⚠️ Please complete analysis first!")
        st.info("👉 Run: Upload Logs → Anomaly Detection → Event Correlation → Timeline Analysis")
    else:
        from modules.report_generator import generate_forensic_report
        
        st.success("✅ Ready to generate forensic report")
        
        # Report generation controls
        col1, col2 = st.columns([3, 1])
        
        with col1:
            st.info("📝 Click the button to generate a comprehensive AI-powered forensic analysis report")
        
        with col2:
            generate_btn = st.button("📝 Generate Report", type="primary")
        
        # Generate report
        if generate_btn or 'forensic_report' in st.session_state:
            
            if generate_btn:
                with st.spinner("📝 Generating comprehensive forensic report..."):
                    try:
                        # Gather all analysis results
                        logs_df = st.session_state.logs_data
                        anomaly_df = st.session_state.anomalies
                        correlation_results = st.session_state.get('correlation_results', None)
                        timeline_results = st.session_state.get('timeline_results', None)
                        log_stats = st.session_state.get('log_stats', None)
                        
                        # Generate report
                        report = generate_forensic_report(
                            logs_df=logs_df,
                            anomaly_df=anomaly_df,
                            correlation_results=correlation_results,
                            timeline_results=timeline_results,
                            log_stats=log_stats
                        )
                        
                        # Store in session state
                        st.session_state.forensic_report = report
                        
                        st.success("✅ Forensic report generated successfully!")
                        
                    except Exception as e:
                        st.error(f"❌ Error generating report: {str(e)}")
                        st.exception(e)
            
            # Display report
            if 'forensic_report' in st.session_state:
                report = st.session_state.forensic_report
                
                st.markdown("---")
                
                # Report preview tabs
                tab1, tab2 = st.tabs(["📄 Report Preview", "📥 Download Options"])
                
                with tab1:
                    st.markdown("### 📄 Full Forensic Report")
                    
                    # Display report in expandable container
                    with st.container():
                        st.markdown(report)
                
                with tab2:
                    st.markdown("### 📥 Download Report")
                    
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.markdown("#### Markdown Format")
                        st.download_button(
                            label="📥 Download as .md",
                            data=report,
                            file_name=f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                            mime="text/markdown",
                            use_container_width=True
                        )
                        st.caption("✅ Best for viewing in Markdown editors")
                    
                    with col2:
                        st.markdown("#### Text Format")
                        st.download_button(
                            label="📥 Download as .txt",
                            data=report,
                            file_name=f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                            mime="text/plain",
                            use_container_width=True
                        )
                        st.caption("✅ Universal text format")
                    
                    with col3:
                        st.markdown("#### HTML Format")
                        # Convert Markdown to simple HTML
                        html_report = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Forensic Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; }}
        h1, h2, h3 {{ color: #00ff41; }}
        code {{ background: #f4f4f4; padding: 2px 5px; border-radius: 3px; }}
        pre {{ background: #f4f4f4; padding: 10px; border-radius: 5px; overflow-x: auto; }}
    </style>
</head>
<body>
    <pre>{report}</pre>
</body>
</html>
"""
                        st.download_button(
                            label="📥 Download as .html",
                            data=html_report,
                            file_name=f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
                            mime="text/html",
                            use_container_width=True
                        )
                        st.caption("✅ Can be opened in any browser")
                    
                    st.markdown("---")
                    st.info("💡 **Tip:** Save the Markdown file and use tools like Pandoc or online converters to generate PDF reports")
                
                st.markdown("---")
                
                # Report statistics
                st.markdown("### 📊 Report Statistics")
                
                col1, col2, col3, col4 = st.columns(4)
                
                with col1:
                    word_count = len(report.split())
                    st.metric("Word Count", f"{word_count:,}")
                
                with col2:
                    line_count = len(report.split('\n'))
                    st.metric("Lines", f"{line_count:,}")
                
                with col3:
                    char_count = len(report)
                    st.metric("Characters", f"{char_count:,}")
                
                with col4:
                    # Estimate reading time (average 200 words per minute)
                    reading_time = max(1, word_count // 200)
                    st.metric("Reading Time", f"{reading_time} min")
                
                st.markdown("---")
                
                # Key highlights from report
                st.markdown("### 🎯 Report Highlights")
                
                if st.session_state.anomalies is not None:
                    anomalies = st.session_state.anomalies
                    critical_count = (anomalies['severity_level'] == 'CRITICAL').sum()
                    high_count = (anomalies['severity_level'] == 'HIGH').sum()
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        if critical_count > 0:
                            st.error(f"🚨 **{critical_count}** CRITICAL severity events detected")
                        elif high_count > 0:
                            st.warning(f"⚠️ **{high_count}** HIGH severity events detected")
                        else:
                            st.success("✅ No critical security incidents detected")
                    
                    with col2:
                        if st.session_state.get('correlation_results'):
                            chains = st.session_state.correlation_results['attack_chains_detected']
                            if chains > 0:
                                st.warning(f"🔗 **{chains}** attack chain(s) identified")
                            else:
                                st.info("ℹ️ No multi-stage attacks detected")
        
        else:
            st.info("👆 Click 'Generate Report' to create the forensic analysis document")
            
            # Show what will be included
            st.markdown("---")
            st.markdown("### 📋 Report Contents")
            
            st.markdown("""
            The generated report will include:
            
            **📊 Executive Summary**
            - Overall severity assessment
            - Key findings and statistics
            - Immediate action recommendations
            
            **📋 Incident Overview**
            - Timeline and duration
            - Affected assets (users, IPs, resources)
            - Attack surface analysis
            
            **🔬 Technical Analysis**
            - Machine learning detection results
            - Attack chain correlation findings
            - Cyber kill chain phase mapping
            
            **⏱️ Attack Timeline**
            - Chronological event sequence
            - Phase progression narrative
            - Critical period identification
            
            **📁 Evidence Summary**
            - Top 10 most suspicious events
            - Detailed event information
            - Anomaly explanations
            
            **🚩 Indicators of Compromise (IOCs)**
            - Suspicious IP addresses
            - Compromised user accounts
            - Malicious actions and resources
            
            **🎯 Confidence Assessment**
            - ML model confidence scores
            - Correlation confidence metrics
            - Overall analysis reliability
            
            **💡 Recommendations**
            - Immediate actions required
            - Short-term mitigation steps
            - Long-term security improvements
            - Technical hardening measures
            
            **📎 Appendix**
            - Methodology and techniques
            - Data sources and quality
            - Model parameters
            """)

# ============================================================================
# FOOTER
# ============================================================================

st.markdown("---")
st.markdown(
    """
    <div style='text-align: center; color: #00ff41;'>
        🔍 Cyber Forensics AI v1.0.0 | Built with Streamlit + ML | Hackathon 2025
    </div>
    """,
    unsafe_allow_html=True
)