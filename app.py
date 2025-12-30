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
from modules.playbooks.playbook_manager import PlaybookManager


# Page configuration
st.set_page_config(
    page_title="Cyber Forensics AI Dashboard",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)


def load_css():
    # Load existing CSS files FIRST
    for css_file in ["assets/style.css", "assets/custom_theme.css"]:
        try:
            with open(css_file) as f:
                css = f.read()
                st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)
        except FileNotFoundError:
            pass
    
    # Your existing button styling
    button_css = """
    <style>
    .stButton>button, .stDownloadButton>button {
        background: #00ff41 !important;
        color: #232946 !important;
        border: none !important;
        box-shadow: none !important;
        transition: background 0.2s;
    }
    .stButton>button:hover, .stDownloadButton>button:hover {
        background: #00e63a !important;
        color: #232946 !important;
    }
    </style>
    """
    st.markdown(button_css, unsafe_allow_html=True)
    
    # NOW load background image LAST (so it overrides everything)
    try:
        import base64
        with open("bg.png", "rb") as f:
            banner_data = base64.b64encode(f.read()).decode()
        st.markdown(f"""
        <style>
        .stApp {{
            background-image: url('data:image/png;base64,{banner_data}') !important;
            background-size: cover !important;
            background-position: center !important;
            background-repeat: no-repeat !important;
            background-attachment: fixed !important;
        }}
        </style>
        """, unsafe_allow_html=True)
    except FileNotFoundError:
        pass  # Background won't show if file missing

# ✅ ADD THIS LINE TO ACTUALLY CALL THE FUNCTION
load_css()
# --- Main Title (centered, no header bar) ---
st.markdown("""
<div style='text-align:center;margin-top:1.5em;'>
    <h1 style="margin:0;font-size:4rem;font-weight:900;color:#232323;text-align:center;letter-spacing:1px;font-family:'Montserrat', 'Segoe UI', Arial, sans-serif;">Cyber Forensics AI</h1>
</div>
""", unsafe_allow_html=True)

# --- Subtitle below header bar ---
st.markdown("""
<div style='text-align:center;margin-top:1.5em;'>
    <span style='font-size:1.2em; color:#7fdbff;'>Upload your log files, run a full forensic analysis pipeline, and download a professional report. <b>All in one place.</b></span>
</div>
<hr style='border:1px solid #232946; margin-top:1.2em; margin-bottom:1.2em;'>
""", unsafe_allow_html=True)


# Initialize session state for all steps
for key, default in [
    ('logs_data', None),
    ('log_stats', None),
    ('log_validation', None),
    ('anomalies', None),
    ('anomaly_results', None),
    ('attack_chains', None),
    ('correlation_results', None),
    ('timeline_results', None),
    ('forensic_report', None),
    ('pdf_report', None),
    ('analysis_complete', False),
    ('upload_mode', None),
    ('prediction_results', None)
]:
    if key not in st.session_state:
        st.session_state[key] = default



# --- Upload Section ---
from modules.log_parser import parse_logs, parse_multiple_logs
upload_mode = st.radio(
    "Select Upload Mode:",
    ["📄 Single File", "📚 Multiple Files (Enterprise Mode)"],
    horizontal=True
)


# --- Unified Upload Section ---
if upload_mode == "📄 Single File":
    uploaded_file = st.file_uploader(
        "Choose a log file",
        type=['csv', 'json'],
        help="Upload CSV or JSON log files for forensic analysis"
    )
    uploaded_files = [uploaded_file] if uploaded_file else []
else:
    uploaded_files = st.file_uploader(
        "Choose log files (multiple)",
        type=['csv', 'json'],
        accept_multiple_files=True,
        help="Upload multiple CSV or JSON log files for enterprise-wide forensic analysis"
    ) or []


# --- Begin Process & Clear Button ---
col_begin, col_clear = st.columns([3,1])
with col_begin:
    begin = st.button("🚦 Begin Process", type="primary")
with col_clear:
    clear = st.button("🧹 Clear", type="secondary")

# --- Clear Button Logic ---
# --- Clear Button Logic ---
if 'clear' not in st.session_state:
    st.session_state['clear'] = False
if clear:
    for key in [
        'logs_data', 'log_stats', 'log_validation', 'anomalies', 'anomaly_results',
        'attack_chains', 'correlation_results', 'timeline_results', 'forensic_report',
        'pdf_report', 'pdf_bytes', 'analysis_complete', 'upload_mode', 'prediction_results'
    ]:
        if key in st.session_state:
            del st.session_state[key]
    st.rerun()

# --- Main Dashboard Tabs ---
if uploaded_files and begin:
    # Parse logs (single or multi)
    with st.spinner("🔄 Parsing and normalizing log file(s)..."):
        try:
            if upload_mode == "📄 Single File":
                file_type = 'csv' if uploaded_files[0].name.endswith('.csv') else 'json'
                df, stats, validation = parse_logs(uploaded_files[0], file_type)
                df['source_file'] = uploaded_files[0].name
            else:
                file_buffers_list = []
                for f in uploaded_files:
                    if f.name.endswith('.csv'):
                        file_type = 'csv'
                    elif f.name.endswith('.json'):
                        file_type = 'json'
                    else:
                        continue
                    file_buffers_list.append((f, f.name, file_type))
                df, stats, validation = parse_multiple_logs(file_buffers_list)
                if 'source_file' not in df.columns:
                    df['source_file'] = df.get('source_file', 'unknown')
            st.session_state.logs_data = df
            st.session_state.log_stats = stats
            st.session_state.log_validation = validation
            st.session_state.upload_mode = 'single' if upload_mode == "📄 Single File" else 'multi'
            st.success(f"✅ Successfully parsed and normalized {len(df)} log entries!")
        except Exception as e:
            st.error(f"❌ Error parsing file(s): {str(e)}")
            st.stop()

    # --- Run Anomaly Detection ---
    from modules.anomaly_detector import detect_anomalies
    with st.spinner("🧠 Running ML-based anomaly detection..."):
        try:
            results, anomaly_df = detect_anomalies(st.session_state.logs_data, contamination=0.1)
            st.session_state.anomalies = anomaly_df
            st.session_state.anomaly_results = results
            st.session_state.analysis_complete = True
        except Exception as e:
            st.error(f"❌ Error during anomaly detection: {str(e)}")
            st.stop()

    # --- Run Event Correlation ---
    from modules.event_correlator import correlate_events
    try:
        results, chains = correlate_events(
            st.session_state.logs_data,
            st.session_state.anomalies,
            time_window=30
        )
        st.session_state.attack_chains = chains
        st.session_state.correlation_results = results
    except Exception as e:
        st.error(f"❌ Error during event correlation: {str(e)}")
        st.stop()

    # --- Run Timeline Analysis ---
    from modules.timeline_builder import build_timeline
    try:
        timeline_results = build_timeline(
            st.session_state.logs_data,
            st.session_state.anomalies,
            st.session_state.attack_chains
        )
        st.session_state.timeline_results = timeline_results
    except Exception as e:
        st.error(f"❌ Error during timeline reconstruction: {str(e)}")
        st.stop()

# --- Results Tabs ---
if st.session_state.logs_data is not None and st.session_state.anomalies is not None and st.session_state.attack_chains is not None and st.session_state.timeline_results is not None:
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "📋 Parsed Logs", "🔎 Anomaly Detection", "🔗 Event Correlation", "⏱️ Timeline Analysis", "🔮 Attack Prediction", "📊 Forensic Report"
    ])

    with tab1:
        # Show parsed logs, stats, validation, etc.
        stats = st.session_state.log_stats
        df = st.session_state.logs_data
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
        st.markdown("#### 📅 Time Range")
        col1, col2 = st.columns(2)
        with col1:
            st.write("**Start:**", stats['date_range']['start'])
        with col2:
            st.write("**End:**", stats['date_range']['end'])
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
        st.markdown("### 📋 Normalized Log Preview (First 20 entries)")
        st.dataframe(df.head(20), use_container_width=True)
        st.markdown("### 🔍 Data Schema")
        col1, col2 = st.columns(2)
        with col1:
            st.write("**Normalized Fields:**")
            st.write(stats['fields_present'][:10])
        with col2:
            st.write("**Shape:**", df.shape)
            st.write("**Memory Usage:**", f"{df.memory_usage(deep=True).sum() / 1024:.2f} KB")
        st.markdown("#### 🎯 Top 10 Actions")
        action_df = pd.DataFrame({
            'Action': list(stats['action_distribution'].keys()),
            'Count': list(stats['action_distribution'].values())
        })
        st.dataframe(action_df, use_container_width=True)


    with tab2:
        # --- Anomaly Detection Tab ---
        results = st.session_state.anomaly_results
        anomaly_df = st.session_state.anomalies
        st.markdown("### 📊 Detection Results")
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Normal Events", results['normal_events'], delta=f"{100-results['anomaly_percentage']:.1f}%")
        with col2:
            st.metric("Anomalies Detected", results['anomalies_detected'], delta=f"{results['anomaly_percentage']:.1f}%", delta_color="inverse")
        with col3:
            critical_count = (anomaly_df['severity_level'] == 'CRITICAL').sum()
            st.metric("Critical Severity", critical_count, delta="Urgent" if critical_count > 0 else "None")
        with col4:
            st.metric("Max Anomaly Score", f"{results['max_anomaly_score']:.2f}", delta="0.0 - 1.0 scale")
        st.markdown("### 🎯 Anomaly Score Distribution")
        fig = go.Figure()
        normal_scores = anomaly_df[anomaly_df['is_anomaly'] == 0]['anomaly_score']
        anomaly_scores = anomaly_df[anomaly_df['is_anomaly'] == 1]['anomaly_score']
        fig.add_trace(go.Histogram(x=normal_scores, nbinsx=30, name='Normal Events', marker_color='#00ff41', opacity=0.7))
        fig.add_trace(go.Histogram(x=anomaly_scores, nbinsx=30, name='Anomalies', marker_color='#ff4136', opacity=0.7))
        fig.update_layout(title='Anomaly Score Distribution', xaxis_title='Anomaly Score (0 = Normal, 1 = Highly Anomalous)', yaxis_title='Frequency', barmode='overlay', plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)', font=dict(color='#fafafa'), showlegend=True)
        st.plotly_chart(fig, use_container_width=True)
        st.markdown("### 🚨 Severity Distribution")
        severity_counts = anomaly_df['severity_level'].value_counts()
        fig2 = px.pie(values=severity_counts.values, names=severity_counts.index, title='Event Severity Levels', color=severity_counts.index, color_discrete_map={'NORMAL': '#00ff41', 'LOW': '#7fdbff', 'MEDIUM': '#ffdc00', 'HIGH': '#ff851b', 'CRITICAL': '#ff4136'})
        fig2.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)', font=dict(color='#fafafa'))
        st.plotly_chart(fig2, use_container_width=True)
        st.markdown("### 🔍 Feature Importance")
        st.info("Shows which features contribute most to anomaly detection")
        importance = results['feature_importance']
        top_features = dict(list(importance.items())[:10])
        fig3 = px.bar(x=list(top_features.values()), y=list(top_features.keys()), orientation='h', title='Top 10 Most Important Features', labels={'x': 'Importance Score', 'y': 'Feature'}, color=list(top_features.values()), color_continuous_scale='Greens')
        fig3.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)', font=dict(color='#fafafa'), showlegend=False)
        st.plotly_chart(fig3, use_container_width=True)
        st.markdown("### ⚠️ Detected Anomalies")
        anomalies_only = anomaly_df[anomaly_df['is_anomaly'] == 1].sort_values('anomaly_score', ascending=False)
        if len(anomalies_only) > 0:
            st.write(f"**Showing {len(anomalies_only)} anomalous events:**")
            display_cols = ['event_id', 'timestamp', 'user', 'action', 'ip_address', 'result', 'anomaly_score', 'severity_level', 'explanation']
            st.dataframe(anomalies_only[display_cols].head(20), use_container_width=True)
            csv = anomalies_only.to_csv(index=False)
            st.download_button(label="📥 Download Anomalies as CSV", data=csv, file_name="detected_anomalies.csv", mime="text/csv")
        else:
            st.info("✅ No anomalies detected in the dataset!")

    with tab3:
        # --- Event Correlation Tab ---
        results = st.session_state.correlation_results
        chains = st.session_state.attack_chains
        st.markdown("### 📊 Correlation Results")
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Attack Chains", results['attack_chains_detected'], delta="Multi-stage")
        with col2:
            st.metric("Correlated Events", results['correlated_events'], delta=f"{results['correlated_events']/results['total_events']*100:.1f}%")
        with col3:
            st.metric("Unique Attackers", results['unique_attackers'], delta="IP addresses")
        with col4:
            critical_chains = sum(1 for c in chains if c['severity'] == 'CRITICAL')
            st.metric("Critical Chains", critical_chains, delta="Urgent" if critical_chains > 0 else "None")
        if len(chains) > 0:
            st.markdown("### 🕸️ Attack Correlation Graph")
            st.info("Interactive graph showing relationships between correlated events")
            from utils.visualization import create_attack_chain_graph, create_timeline_chart
            graph = results['graph']
            fig_graph = create_attack_chain_graph(graph)
            st.plotly_chart(fig_graph, use_container_width=True)
            st.markdown("### 🎯 Detected Attack Chains")
            for idx, chain in enumerate(chains):
                severity_colors = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
                severity_icon = severity_colors.get(chain['severity'], '⚪')
                with st.expander(f"{severity_icon} **{chain['chain_id']}** - {chain['pattern']} (" f"{chain['event_count']} events, {chain['severity']} severity)", expanded=(idx == 0)):
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
                    st.markdown("**Event Sequence:**")
                    chain_df = pd.DataFrame(chain['events'])
                    display_cols = ['timestamp', 'user', 'action', 'resource', 'ip_address', 'result', 'anomaly_score']
                    chain_df['#'] = range(1, len(chain_df) + 1)
                    display_cols = ['#'] + display_cols
                    st.dataframe(chain_df[display_cols], use_container_width=True, hide_index=True)
                    st.markdown("**Timeline Visualization:**")
                    fig_timeline = create_timeline_chart(chain)
                    st.plotly_chart(fig_timeline, use_container_width=True)
            st.markdown("### 📋 Attack Pattern Summary")
            pattern_counts = {}
            for chain in chains:
                pattern = chain['pattern']
                pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1
            pattern_df = pd.DataFrame({'Attack Pattern': list(pattern_counts.keys()), 'Occurrences': list(pattern_counts.values())}).sort_values('Occurrences', ascending=False)
            fig_patterns = px.bar(pattern_df, x='Occurrences', y='Attack Pattern', orientation='h', title='Attack Pattern Distribution', color='Occurrences', color_continuous_scale='Reds')
            fig_patterns.update_layout(plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)', font=dict(color='#fafafa'))
            st.plotly_chart(fig_patterns, use_container_width=True)
        else:
            st.info("✅ No attack chains detected - all events appear isolated")

    with tab4:
        # --- Timeline Analysis Tab ---
        results = st.session_state.timeline_results
        stats = results['stats']
        timeline_df = results['timeline_df']
        from utils.visualization import create_gantt_timeline, create_phase_distribution_chart, create_temporal_heatmap
        st.markdown("### 📊 Timeline Overview")
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Events", stats['total_events'])
        with col2:
            duration_hours = stats['time_span'].total_seconds() / 3600
            st.metric("Duration", f"{duration_hours:.1f}h" if duration_hours >= 1 else f"{stats['time_span'].total_seconds()/60:.0f}m")
        with col3:
            st.metric("Kill Chain Phases", stats['phases_observed'])
        with col4:
            st.metric("High-Risk Events", stats['high_risk_phases'], delta="Critical" if stats['high_risk_phases'] > 0 else "None")
        col1, col2 = st.columns(2)
        with col1:
            st.info(f"**Start:** {stats['start_time']}")
        with col2:
            st.info(f"**End:** {stats['end_time']}")
        st.markdown("### 📖 Attack Narrative")
        with st.expander("View AI-Generated Attack Story", expanded=True):
            st.markdown(results['narrative'])
        st.markdown("### 📅 Interactive Timeline")
        st.info("Events colored by anomaly severity | Click and drag to zoom")
        fig_gantt = create_gantt_timeline(results['timeline_events'])
        st.plotly_chart(fig_gantt, use_container_width=True)
        st.markdown("### 🎯 Kill Chain Phase Analysis")
        col1, col2 = st.columns([1, 1])
        with col1:
            st.markdown("### Phase Distribution")
            fig_phases = create_phase_distribution_chart(results['phase_distribution'])
            st.plotly_chart(fig_phases, use_container_width=True)
        with col2:
            st.markdown("### Phase Summary")
            st.markdown(results['phase_summary'])
        st.markdown("### 🔥 Temporal Activity Heatmap")
        st.info("Shows when attacks occurred - darker = more activity")
        fig_heatmap = create_temporal_heatmap(timeline_df)
        st.plotly_chart(fig_heatmap, use_container_width=True)
        if results['critical_periods']:
            st.markdown("### ⚠️ Critical Time Periods")
            st.write(f"**{len(results['critical_periods'])} high-activity periods detected:**")
            for period in results['critical_periods'][:10]:
                severity_color = '🔴' if period['severity'] == 'CRITICAL' else '🟠'
                st.warning(f"{severity_color} **{period['start']}** to **{period['end']}** | {period['event_count']} events | Avg Anomaly: {period['avg_anomaly']:.2f}")
        st.markdown("### 📋 Detailed Event Timeline")
        col1, col2, col3 = st.columns(3)
        with col1:
            phase_filter = st.multiselect("Filter by Phase:", options=timeline_df['kill_chain_phase'].unique().tolist(), default=[])
        with col2:
            severity_filter = st.multiselect("Filter by Severity:", options=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NORMAL'], default=[])
        with col3:
            show_anomalies_only = st.checkbox("Show Anomalies Only")
        filtered_df = timeline_df.copy()
        if phase_filter:
            filtered_df = filtered_df[filtered_df['kill_chain_phase'].isin(phase_filter)]
        if severity_filter:
            filtered_df = filtered_df[filtered_df['severity_level'].isin(severity_filter)]
        if show_anomalies_only:
            filtered_df = filtered_df[filtered_df['anomaly_score'] > 0.6]
        display_cols = ['sequence', 'timestamp', 'kill_chain_phase', 'action', 'user', 'ip_address', 'resource', 'result', 'anomaly_score', 'severity_level']
        st.dataframe(filtered_df[display_cols], use_container_width=True, height=400)
        csv = filtered_df.to_csv(index=False)
        st.download_button(label="📥 Download Timeline as CSV", data=csv, file_name="attack_timeline.csv", mime="text/csv")

    with tab5:
        # --- Attack Prediction Tab ---
        st.markdown("### 🔮 AI-Powered Attack Prediction")
        st.info("📚 Using comprehensive playbook knowledge base to predict attack progression and recommend countermeasures")
        
        from modules.playbooks.playbook_manager import PlaybookManager
        
        # Initialize playbook manager
        if 'playbook_manager' not in st.session_state:
            with st.spinner("🔄 Loading playbook library..."):
                st.session_state.playbook_manager = PlaybookManager()
        
        manager = st.session_state.playbook_manager
        
        # Identify attacks from current data
        st.markdown("### 🎯 Attack Identification")
        
        # Build log patterns from actual data
        anomaly_df = st.session_state.anomalies
        chains = st.session_state.attack_chains
        
        # Build comprehensive log patterns from actual data with safe column checks
        log_patterns = {}
        
        # Failed logins
        if 'action' in anomaly_df.columns and 'result' in anomaly_df.columns:
            log_patterns['failed_logins'] = len(anomaly_df[
                anomaly_df['action'].str.contains('login', case=False, na=False) & 
                (anomaly_df['result'] == 'FAILED')
            ])
        else:
            log_patterns['failed_logins'] = 0
        
        # SQL injection keywords
        sql_count = 0
        if 'resource' in anomaly_df.columns:
            sql_count += len(anomaly_df[
                anomaly_df['resource'].str.contains('SELECT|UNION|DROP|INSERT|UPDATE|DELETE|information_schema', case=False, na=False)
            ])
        if 'action' in anomaly_df.columns:
            sql_count += len(anomaly_df[
                anomaly_df['action'].str.contains('SELECT|UNION|DROP|INSERT', case=False, na=False)
            ])
        log_patterns['sql_keywords'] = sql_count
        
        # SQL errors
        if 'result' in anomaly_df.columns:
            log_patterns['sql_errors'] = len(anomaly_df[anomaly_df['result'] == 'ERROR'])
        else:
            log_patterns['sql_errors'] = 0
        
        # Mass file modifications
        if 'action' in anomaly_df.columns:
            log_patterns['mass_file_modifications'] = len(anomaly_df[
                anomaly_df['action'].str.contains('file_modify|file_write|modify|write|delete', case=False, na=False)
            ])
        else:
            log_patterns['mass_file_modifications'] = 0
        
        # Encrypted file extensions
        if 'resource' in anomaly_df.columns:
            log_patterns['encrypted_extensions'] = len(anomaly_df[
                anomaly_df['resource'].str.contains('.encrypted|.locked|.crypto|.crypt', case=False, na=False)
            ])
        else:
            log_patterns['encrypted_extensions'] = 0
        
        # Ransom note files
        if 'resource' in anomaly_df.columns:
            log_patterns['ransom_note_files'] = len(anomaly_df[
                anomaly_df['resource'].str.contains('README|HOW_TO_DECRYPT|DECRYPT_FILES|RECOVER_FILES|ransom', case=False, na=False)
            ])
        else:
            log_patterns['ransom_note_files'] = 0
        
        # Shadow copy deletion
        if 'resource' in anomaly_df.columns:
            log_patterns['shadow_copy_deletion'] = len(anomaly_df[
                anomaly_df['resource'].str.contains('vssadmin|shadow|bcdedit|wbadmin', case=False, na=False)
            ])
        else:
            log_patterns['shadow_copy_deletion'] = 0
        
        # File renames
        if 'action' in anomaly_df.columns:
            log_patterns['file_renames'] = len(anomaly_df[
                anomaly_df['action'].str.contains('file_rename|rename', case=False, na=False)
            ])
        else:
            log_patterns['file_renames'] = 0
        
        # Backup deletion
        if 'action' in anomaly_df.columns and 'resource' in anomaly_df.columns:
            log_patterns['backup_deletion'] = len(anomaly_df[
                (anomaly_df['action'].str.contains('file_delete|delete', case=False, na=False)) &
                (anomaly_df['resource'].str.contains('backup|.bak|.bkp', case=False, na=False))
            ])
        else:
            log_patterns['backup_deletion'] = 0
        
        # Unusual IP count
        if 'ip_address' in anomaly_df.columns:
            log_patterns['unusual_ip'] = len(anomaly_df['ip_address'].unique()) > 10
        else:
            log_patterns['unusual_ip'] = False
        
        # High data transfer (SAFE CHECK)
        if 'bytes_transferred' in anomaly_df.columns:
            log_patterns['high_data_transfer'] = len(anomaly_df[anomaly_df['bytes_transferred'] > 500000])
        else:
            log_patterns['high_data_transfer'] = 0
        detected_attacks = manager.identify_attack(log_patterns)
        
        if detected_attacks:
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Attacks Identified", len(detected_attacks))
            with col2:
                st.metric("Highest Confidence", f"{detected_attacks[0]['confidence']:.0%}")
            with col3:
                st.metric("Severity", detected_attacks[0]['severity'])
            
            # Show detected attacks
            st.markdown("#### 🚨 Detected Attack Types:")
            for attack in detected_attacks:
                with st.expander(f"{'🔴' if attack['severity'] == 'CRITICAL' else '🟠'} {attack['attack_name']} (Confidence: {attack['confidence']:.0%})", expanded=(attack == detected_attacks[0])):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write(f"**Attack ID:** {attack['attack_id']}")
                        st.write(f"**Confidence:** {attack['confidence']:.0%}")
                        st.write(f"**Severity:** {attack['severity']}")
                    with col2:
                        st.write(f"**Detection Reason:**")
                        st.write(attack['reason'])
            
            # Detailed prediction for top attack
            st.markdown("---")
            st.markdown("### 📊 Comprehensive Attack Analysis")
            
            top_attack = detected_attacks[0]
            attack_id = top_attack['attack_id']
            
            # Determine current stage based on attack chains
            # Determine current stage based on behavioral analysis
            current_stage = 1  # Default: Reconnaissance
            
            # Stage detection based on attack type
            if attack_id == "ATK-AUTH-001":  # Brute Force
                if log_patterns['failed_logins'] > 50:
                    current_stage = 3  # Successful authentication likely
                elif log_patterns['failed_logins'] > 20:
                    current_stage = 2  # Active brute forcing
                else:
                    current_stage = 1  # Initial attempts
                    
            elif attack_id == "ATK-INJ-001":  # SQL Injection
                # Check for data extraction indicators
                if log_patterns.get('high_data_transfer', 0) > 5:
                    current_stage = 4  # Data exfiltration stage
                elif log_patterns['sql_keywords'] > 15:
                    current_stage = 3  # Database enumeration
                elif log_patterns['sql_keywords'] > 5:
                    current_stage = 2  # Exploitation attempts
                else:
                    current_stage = 1  # Initial probing
                    
            elif attack_id == "ATK-MAL-001":  # Ransomware
                # Check ransomware progression
                if log_patterns.get('ransom_note_files', 0) > 0:
                    current_stage = 5  # Ransom demand (final stage)
                elif log_patterns.get('encrypted_extensions', 0) > 10:
                    current_stage = 5  # Mass encryption in progress
                elif log_patterns.get('shadow_copy_deletion', 0) > 0:
                    current_stage = 3  # Removing recovery options
                elif log_patterns.get('mass_file_modifications', 0) > 50:
                    current_stage = 4  # Lateral movement/encryption starting
                else:
                    current_stage = 2  # Initial compromise
            
            # Use attack chains as additional indicator
            if len(chains) > 2:
                current_stage = min(current_stage + 1, 5)  # Advance stage but cap at 5
            
            # Get full analysis
            full_analysis = manager.get_full_attack_analysis(attack_id, current_stage)
            
            # Overview
            st.markdown("#### 🎯 Attack Overview")
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Attack Type", full_analysis['attack_overview']['category'])
            with col2:
                st.metric("Current Stage", f"{current_stage}/{full_analysis['attack_stages']['total_stages']}")
            with col3:
                st.metric("Typical Duration", full_analysis['timing_analysis']['typical_duration'])
            with col4:
                st.metric("Attack Speed", full_analysis['timing_analysis']['attack_speed'])
            
            st.markdown(f"**Description:** {full_analysis['attack_overview']['description']}")
            
            # Next Stage Prediction
            st.markdown("---")
            st.markdown("### 🔮 Next Stage Prediction")
            
            prediction = manager.predict_next_stage(attack_id, current_stage)
            
            if prediction.get('next_stage', {}).get('stage_name'):
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Next Stage", prediction['next_stage']['stage_name'])
                with col2:
                    st.metric("Probability", prediction['next_stage']['probability'])
                with col3:
                    st.metric("Next Stage Severity", prediction['next_stage']['severity'])
                
                # Timing prediction
                st.markdown("#### ⏰ Timing Prediction")
                timing = prediction['timing']
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.info(f"**Earliest:** {timing['predicted_time_window']['earliest']}")
                with col2:
                    st.warning(f"**Most Likely:** {timing['predicted_time_window']['most_likely']}")
                with col3:
                    st.error(f"**Latest:** {timing['predicted_time_window']['latest']}")
                
                st.write(f"⏱️ **Detection Window Remaining:** {timing['detection_window_remaining']} minutes")
                
                # Target prediction
                st.markdown("#### 🎯 Likely Target")
                target = prediction['likely_targets']
                if target['primary']:
                    col1, col2 = st.columns(2)
                    with col1:
                        st.error(f"**Primary Target:** {target['primary']}")
                        st.write(f"**Probability:** {target['probability']}")
                    with col2:
                        st.error(f"**Estimated Damage:** {target['estimated_damage']}")
                
                # Point of no return
                st.markdown("---")
                st.markdown("### ⚠️ Point of No Return")
                ponr = prediction['point_of_no_return']
                
                if ponr['can_still_stop']:
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.success(f"**Status:** {ponr['status']}")
                    with col2:
                        st.warning(f"**Time Remaining:** {ponr['minutes_remaining']} minutes")
                    with col3:
                        st.info(f"**Stages Until PONR:** {ponr['stages_remaining']}")
                    
                    st.write(f"🚨 **Critical Time:** {ponr['critical_time']}")
                else:
                    st.error("🚨 **CRITICAL:** Attack has reached point of no return!")
            
            # Recommended Actions
            st.markdown("---")
            st.markdown("### 🛡️ Recommended Immediate Actions")
            
            actions = prediction.get('recommended_actions', [])
            if actions:
                for i, action in enumerate(actions, 1):
                    with st.container():
                        col1, col2, col3 = st.columns([3, 1, 1])
                        with col1:
                            st.write(f"**{i}. {action['action']}**")
                        with col2:
                            st.success(f"✅ {action['effectiveness']}")
                        with col3:
                            st.info(f"⏱️ {action['time']}")
            
            # Attacker Profile Analysis
            # Attacker Profile Analysis
            st.markdown("---")
            st.markdown("### 👤 Attacker Profile Analysis")
            
            # Smart behavioral analysis based on attack type and sophistication
            behavioral_data = {}
            
            # Determine automation usage
            if attack_id == "ATK-AUTH-001":  # Brute Force
                behavioral_data['uses_automation'] = log_patterns.get('failed_logins', 0) > 30
                behavioral_data['persistence'] = 'low' if log_patterns.get('failed_logins', 0) < 30 else 'medium'
                behavioral_data['tools_used'] = ['hydra', 'automated_tools'] if log_patterns.get('failed_logins', 0) > 50 else ['manual_tools']
                
            elif attack_id == "ATK-INJ-001":  # SQL Injection
                sql_count = log_patterns.get('sql_keywords', 0)
                behavioral_data['uses_automation'] = sql_count > 10
                
                # Sophistication based on number and variety of SQL attacks
                if sql_count > 20 and log_patterns.get('high_data_transfer', 0) > 3:
                    behavioral_data['persistence'] = 'high'  # Cybercriminal
                    behavioral_data['tools_used'] = ['sqlmap', 'custom_scripts', 'automated_tools']
                elif sql_count > 10:
                    behavioral_data['persistence'] = 'medium'  # Intermediate
                    behavioral_data['tools_used'] = ['sqlmap', 'automated_tools']
                else:
                    behavioral_data['persistence'] = 'low'  # Script Kiddie
                    behavioral_data['tools_used'] = ['manual_tools', 'sqlmap']
                    
            elif attack_id == "ATK-MAL-001":  # Ransomware
                behavioral_data['uses_automation'] = True  # Ransomware is always automated
                
                # Sophistication based on tactics
                ransom_indicators = (
                    log_patterns.get('ransom_note_files', 0) +
                    log_patterns.get('shadow_copy_deletion', 0) +
                    log_patterns.get('backup_deletion', 0)
                )
                
                if ransom_indicators >= 3 and log_patterns.get('encrypted_extensions', 0) > 10:
                    behavioral_data['persistence'] = 'high'  # Professional ransomware gang
                    behavioral_data['tools_used'] = ['custom_ransomware', 'automated_tools', 'lateral_movement_tools']
                else:
                    behavioral_data['persistence'] = 'medium'  # Ransomware-as-a-Service user
                    behavioral_data['tools_used'] = ['ransomware_kit', 'automated_tools']
            else:
                # Default
                behavioral_data['uses_automation'] = True
                behavioral_data['persistence'] = 'medium'
                behavioral_data['tools_used'] = ['automated_tools']
            
            # Track covering detection
            covers_tracks_count = 0
            if 'action' in anomaly_df.columns:
                covers_tracks_count = len(anomaly_df[
                    anomaly_df['action'].str.contains('delete|clear|remove|wipe', case=False, na=False)
                ])
            if 'resource' in anomaly_df.columns:
                covers_tracks_count += len(anomaly_df[
                    anomaly_df['resource'].str.contains('log|audit|history', case=False, na=False)
                ])
            
            behavioral_data['covers_tracks'] = covers_tracks_count > 5
            
            # Adjust persistence based on attack chains
            if len(chains) > 3:
                if behavioral_data['persistence'] == 'low':
                    behavioral_data['persistence'] = 'medium'
                elif behavioral_data['persistence'] == 'medium':
                    behavioral_data['persistence'] = 'high'
            
            try:
                attacker_analysis = manager.analyze_behavioral_data(behavioral_data)
                
                if attacker_analysis and 'identified_attacker' in attacker_analysis:
                    col1, col2, col3, col4 = st.columns(4)
                    with col1:
                        st.metric("Attacker Type", attacker_analysis['identified_attacker']['type'])
                    with col2:
                        st.metric("Confidence", attacker_analysis['identified_attacker']['confidence'])
                    with col3:
                        st.metric("Skill Level", attacker_analysis['identified_attacker']['skill_level'])
                    with col4:
                        st.metric("Sophistication", attacker_analysis['identified_attacker']['sophistication'])
                    
                    if attacker_analysis.get('likely_next_actions'):
                        st.markdown("**Likely Next Actions:**")
                        for action in attacker_analysis['likely_next_actions'][:5]:
                            st.write(f"• {action}")
                    
                    st.markdown("**Behavioral Characteristics:**")
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write(f"• **Prefers Stealth:** {attacker_analysis['expected_behaviors']['prefers_stealth']}")
                        st.write(f"• **Covers Tracks:** {attacker_analysis['expected_behaviors']['covers_tracks']}")
                    with col2:
                        st.write(f"• **Typical Duration:** {attacker_analysis['expected_behaviors']['typical_duration']}")
                        st.write(f"• **Success Rate:** {attacker_analysis['expected_behaviors']['success_rate']}")
                else:
                    st.info("ℹ️ Insufficient behavioral data to profile attacker with confidence.")
                    
            except Exception as e:
                st.warning(f"⚠️ Attacker profiling unavailable: Limited behavioral indicators in logs")
                st.info("💡 **Note:** More log data would enable detailed attacker profiling")
        
            # Full Attack Details
            st.markdown("---")
            st.markdown("### 📚 Complete Attack Intelligence")
            
            with st.expander("🔍 View Complete Attack Stages", expanded=False):
                for stage in full_analysis['attack_stages']['stages']:
                    stage_num = stage['number']
                    stage_status = "✅ COMPLETED" if stage_num < current_stage else "🔄 CURRENT" if stage_num == current_stage else "⏳ UPCOMING"
                    
                    st.markdown(f"**Stage {stage_num}: {stage['name']}** {stage_status}")
                    st.write(f"• Description: {stage['description']}")
                    st.write(f"• Duration: {stage['duration']}")
                    st.write(f"• Success Rate: {stage['success_rate']}")
                    st.markdown("---")
            
            with st.expander("🎯 Attacker Motivations & Goals", expanded=False):
                st.markdown("**Primary Motivation:**")
                st.write(full_analysis['attacker_motivations']['primary_motivation'])
                
                st.markdown("**End Goals:**")
                for goal in full_analysis['attacker_motivations']['end_goals']:
                    st.write(f"• {goal}")
                
                st.markdown("**Monetization Methods:**")
                for method in full_analysis['attacker_motivations']['monetization']:
                    st.write(f"• {method}")
            
            with st.expander("🛡️ Available Defensive Strategies", expanded=False):
                st.write(f"**Total Countermeasures Available:** {full_analysis['defensive_strategy']['total_countermeasures']}")
                st.write(f"**Overall Defense Effectiveness:** {full_analysis['defensive_strategy']['overall_effectiveness']}")
                
                st.markdown("**Immediate Actions You Can Take:**")
                for action in full_analysis['defensive_strategy']['immediate_actions'][:5]:
                    st.write(f"• **{action['action']}** (Effectiveness: {action['effectiveness']}, Time: {action['time']})")
            
            with st.expander("💥 Impact Assessment", expanded=False):
                impact = full_analysis['impact_assessment']
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Confidentiality Impact", impact['confidentiality'])
                with col2:
                    st.metric("Integrity Impact", impact['integrity'])
                with col3:
                    st.metric("Availability Impact", impact['availability'])

            st.session_state.prediction_results = {
                'detected_attacks': detected_attacks,
                'next_stage_prediction': prediction if prediction.get('next_stage', {}).get('stage_name') else None,
                'point_of_no_return': prediction.get('point_of_no_return'),
                'attacker_profile': attacker_analysis if 'attacker_analysis' in locals() else None,
                'recommended_actions': prediction.get('recommended_actions', []),
                'full_analysis': full_analysis
            }
        
        else:
            st.success("ZERO DAY ATTACK (No attacks detected based on current log patterns)")
            st.info("The system analyzed your logs but found no patterns matching known attack types.")
            st.session_state.prediction_results = None

    with tab6:
        # --- Forensic Report Tab ---
        from modules.report_generator import generate_forensic_report
        
        st.markdown("### 📊 Forensic Report Generation")
        
        # Generate report ONCE if not already generated
        if 'forensic_report' not in st.session_state or st.session_state.forensic_report is None:
            with st.spinner("📝 Generating comprehensive forensic report..."):
                try:
                    # Get all data (some can be None)
                    logs_df = st.session_state.get('logs_data')
                    anomaly_df = st.session_state.get('anomalies')
                    correlation_results = st.session_state.get('correlation_results')
                    timeline_results = st.session_state.get('timeline_results')
                    log_stats = st.session_state.get('log_stats')
                    prediction_results = st.session_state.get('prediction_results')
                    
                    # Only logs_df and anomaly_df are required
                    if logs_df is None or anomaly_df is None:
                        st.error("❌ Cannot generate report: Missing log data or anomaly detection results")
                        st.info("💡 Please run the complete analysis first by clicking 'Begin Analysis'")
                        st.stop()
                    
                    # Generate report (other params can be None)
                    report = generate_forensic_report(
                        logs_df=logs_df,
                        anomaly_df=anomaly_df,
                        correlation_results=correlation_results,
                        timeline_results=timeline_results,
                        log_stats=log_stats,
                        prediction_results=prediction_results
                    )
                    st.session_state.forensic_report = report
                    st.success("✅ Forensic report generated successfully!")
                    
                except Exception as e:
                    st.error(f"❌ Error generating report: {str(e)}")
                    import traceback
                    with st.expander("🔍 Show detailed error"):
                        st.code(traceback.format_exc())
                    st.session_state.forensic_report = None
                    st.stop()
        
        report = st.session_state.forensic_report
        
        # Check if report was successfully generated
        if report is None:
            st.error("❌ Report generation failed. Please check the errors above.")
            st.stop()
        
        st.markdown("### 📥 Download Report")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown("#### 📄 PDF Format")
            from utils.pdf_generator import generate_pdf_report
            
            # Generate PDF once and cache it in session state
            if 'pdf_bytes' not in st.session_state:
                with st.spinner("📄 Generating PDF..."):
                    try:
                        st.session_state.pdf_bytes = generate_pdf_report(report)
                    except Exception as e:
                        st.error(f"❌ PDF generation error: {str(e)}")
                        st.session_state.pdf_bytes = None
            
            # Direct download button
            if st.session_state.get('pdf_bytes'):
                st.download_button(
                    label="📥 Download as PDF",
                    data=st.session_state.pdf_bytes,
                    file_name=f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                    key="download_pdf"
                )
                st.caption("✅ Professional PDF with formatting")
            else:
                st.error("❌ PDF not available")
                
        with col2:
            st.markdown("#### 📝 Markdown Format")
            st.download_button(
                label="📥 Download as .md", 
                data=report, 
                file_name=f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md", 
                mime="text/markdown", 
                use_container_width=True, 
                type="primary"
            )
            st.caption("✅ Best for version control")
            
        with col3:
            st.markdown("#### 📋 Text Format")
            st.download_button(
                label="📥 Download as .txt", 
                data=report, 
                file_name=f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt", 
                mime="text/plain", 
                use_container_width=True, 
                type="primary"
            )
            st.caption("✅ Universal compatibility")
            
        with col4:
            st.markdown("#### 🌐 HTML Format")
            html_report = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Forensic Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 900px; margin: 0 auto; padding: 20px; background: #0e1117; color: #fafafa; }}
        h1, h2, h3 {{ color: #00ff41; }}
        code {{ background: #1a1d29; padding: 2px 5px; border-radius: 3px; color: #00ff41; }}
        pre {{ background: #1a1d29; padding: 10px; border-radius: 5px; overflow-x: auto; border-left: 3px solid #00ff41; }}
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
                use_container_width=True, 
                type="primary"
            )
            st.caption("✅ Open in any browser")
        
        st.markdown("### 📄 Full Forensic Report")
        with st.container():
            st.markdown(report)
            
        st.markdown("### 📊 Format Comparison")
        format_comparison = pd.DataFrame({
            'Format': ['PDF', 'Markdown', 'Text', 'HTML'],
            'Professional': ['⭐⭐⭐⭐⭐', '⭐⭐⭐⭐', '⭐⭐⭐', '⭐⭐⭐⭐'],
            'Formatting': ['Full', 'Basic', 'None', 'Full'],
            'File Size': ['Large', 'Small', 'Small', 'Medium'],
            'Best For': [
                'Management, Legal, Stakeholders',
                'Developers, Documentation',
                'Quick sharing, Email',
                'Web viewing, Archiving'
            ]
        })
        st.dataframe(format_comparison, use_container_width=True, hide_index=True)
        st.info("💡 **Recommendation:** Use PDF for official reports, Markdown for technical teams")
        
        st.markdown("### 📊 Report Statistics")
        col1, col2, col3, col4 = st.columns(4)
        
        # FIXED: Check if report exists and is a string before calculating stats
        if report and isinstance(report, str):
            word_count = len(report.split())
            line_count = len(report.split('\n'))
            char_count = len(report)
            reading_time = max(1, word_count // 200)
            
            with col1:
                st.metric("Word Count", f"{word_count:,}")
            with col2:
                st.metric("Lines", f"{line_count:,}")
            with col3:
                st.metric("Characters", f"{char_count:,}")
            with col4:
                st.metric("Reading Time", f"{reading_time} min")
        else:
            with col1:
                st.metric("Word Count", "0")
            with col2:
                st.metric("Lines", "0")
            with col3:
                st.metric("Characters", "0")
            with col4:
                st.metric("Reading Time", "0 min")
            
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
                    chains = st.session_state.correlation_results.get('attack_chains_detected', 0)
                    if chains > 0:
                        st.warning(f"🔗 **{chains}** attack chain(s) identified")
                    else:
                        st.info("ℹ️ No multi-stage attacks detected")
if clear:
    for key in [
        'logs_data', 'log_stats', 'log_validation', 'anomalies', 'anomaly_results',
        'attack_chains', 'correlation_results', 'timeline_results', 'forensic_report',
        'pdf_report', 'pdf_bytes', 'analysis_complete', 'upload_mode'  # Added pdf_bytes here
    ]:
        if key in st.session_state:
            del st.session_state[key]
    st.rerun()
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