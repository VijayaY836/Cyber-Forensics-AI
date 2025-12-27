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
    page_title="Cyber Forensics AI Dashboard",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded"
)


def load_css():
    for css_file in ["assets/style.css", "assets/custom_theme.css"]:
        try:
            with open(css_file) as f:
                css = f.read()
                # Remove button contrast effect, force green
                css += """
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
                """
                st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)
        except FileNotFoundError:
            pass
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
    ('upload_mode', None)
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
if 'clear' not in st.session_state:
    st.session_state['clear'] = False
if clear:
    for key in [
        'logs_data', 'log_stats', 'log_validation', 'anomalies', 'anomaly_results',
        'attack_chains', 'correlation_results', 'timeline_results', 'forensic_report',
        'pdf_report', 'analysis_complete', 'upload_mode'
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
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📋 Parsed Logs", "🔎 Anomaly Detection", "🔗 Event Correlation", "⏱️ Timeline Analysis", "📊 Forensic Report"
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
        # --- Forensic Report Tab ---
        from modules.report_generator import generate_forensic_report
        st.success("✅ Ready to generate forensic report")
        if 'forensic_report' not in st.session_state:
            with st.spinner("📝 Generating comprehensive forensic report..."):
                try:
                    logs_df = st.session_state.logs_data
                    anomaly_df = st.session_state.anomalies
                    correlation_results = st.session_state.get('correlation_results', None)
                    timeline_results = st.session_state.get('timeline_results', None)
                    log_stats = st.session_state.get('log_stats', None)
                    report = generate_forensic_report(
                        logs_df=logs_df,
                        anomaly_df=anomaly_df,
                        correlation_results=correlation_results,
                        timeline_results=timeline_results,
                        log_stats=log_stats
                    )
                    st.session_state.forensic_report = report
                    st.success("✅ Forensic report generated successfully!")
                except Exception as e:
                    st.error(f"❌ Error generating report: {str(e)}")
        # Always try to generate the report if missing and analysis is complete
        if 'forensic_report' not in st.session_state or st.session_state.forensic_report is None:
            try:
                from modules.report_generator import generate_forensic_report
                logs_df = st.session_state.logs_data
                anomaly_df = st.session_state.anomalies
                correlation_results = st.session_state.get('correlation_results', None)
                timeline_results = st.session_state.get('timeline_results', None)
                log_stats = st.session_state.get('log_stats', None)
                report = generate_forensic_report(
                    logs_df=logs_df,
                    anomaly_df=anomaly_df,
                    correlation_results=correlation_results,
                    timeline_results=timeline_results,
                    log_stats=log_stats
                )
                st.session_state.forensic_report = report
            except Exception as e:
                st.session_state.forensic_report = None
                st.error(f"❌ Error generating report: {str(e)}")
        report = st.session_state.forensic_report
        st.markdown("### 📥 Download Report")
        col1, col2, col3, col4 = st.columns(4)
        if report is not None:
            with col1:
                st.markdown("#### 📄 PDF Format")
                from utils.pdf_generator import generate_pdf_report
                if st.button("📥 Download as PDF", key="download_pdf", use_container_width=True):
                    with st.spinner("📄 Generating PDF..."):
                        try:
                            pdf_bytes = generate_pdf_report(report)
                            st.download_button(
                                label="📥 Click here to download PDF",
                                data=pdf_bytes,
                                file_name=f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                                mime="application/pdf",
                                use_container_width=True
                            )
                            st.caption("✅ Professional PDF with formatting")
                        except Exception as e:
                            st.error(f"❌ PDF generation error: {str(e)}")
            with col2:
                st.markdown("#### 📝 Markdown Format")
                st.download_button(label="📥 Download as .md", data=report, file_name=f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md", mime="text/markdown", use_container_width=True, type="primary")
                st.caption("✅ Best for version control")
            with col3:
                st.markdown("#### 📋 Text Format")
                st.download_button(label="📥 Download as .txt", data=report, file_name=f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt", mime="text/plain", use_container_width=True, type="primary")
                st.caption("✅ Universal compatibility")
            with col4:
                st.markdown("#### 🌐 HTML Format")
                html_report = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset=\"UTF-8\">
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
                st.download_button(label="📥 Download as .html", data=html_report, file_name=f"forensic_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html", mime="text/html", use_container_width=True, type="primary")
                st.caption("✅ Open in any browser")
        else:
            st.warning("❌ Report content is missing. Please re-run the analysis or check for errors above.")
        st.markdown("### 📄 Full Forensic Report")
        with st.container():
            if report:
                st.markdown(report)
            else:
                st.warning("❌ Report content is missing. Please re-run the analysis or check for errors above.")
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
            reading_time = max(1, word_count // 200)
            st.metric("Reading Time", f"{reading_time} min")
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