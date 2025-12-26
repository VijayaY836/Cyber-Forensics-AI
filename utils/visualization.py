"""
Visualization Utilities
Creates interactive Plotly visualizations for attack chains and graphs
"""

import plotly.graph_objects as go
import networkx as nx
import numpy as np

def create_attack_chain_graph(graph, chain_events=None):
    """
    Create interactive Plotly visualization of attack chain graph
    
    Args:
        graph: NetworkX DiGraph
        chain_events: List of event IDs to highlight (optional)
        
    Returns:
        plotly.graph_objects.Figure: Interactive graph visualization
    """
    if graph.number_of_nodes() == 0:
        # Return empty figure
        fig = go.Figure()
        fig.add_annotation(
            text="No correlated events to display",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False,
            font=dict(size=20, color='#fafafa')
        )
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            xaxis=dict(visible=False),
            yaxis=dict(visible=False)
        )
        return fig
    
    # Use spring layout for graph positioning
    pos = nx.spring_layout(graph, k=2, iterations=50, seed=42)
    
    # Extract edge coordinates
    edge_x = []
    edge_y = []
    
    for edge in graph.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])
    
    # Create edge trace
    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=1, color='#00ff41'),
        hoverinfo='none',
        mode='lines',
        opacity=0.5
    )
    
    # Extract node coordinates and properties
    node_x = []
    node_y = []
    node_text = []
    node_color = []
    node_size = []
    
    for node in graph.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        
        # Get node attributes
        attrs = graph.nodes[node]
        
        # Build hover text
        hover_text = f"<b>{node}</b><br>"
        hover_text += f"Action: {attrs.get('action', 'N/A')}<br>"
        hover_text += f"User: {attrs.get('user', 'N/A')}<br>"
        hover_text += f"IP: {attrs.get('ip_address', 'N/A')}<br>"
        hover_text += f"Time: {attrs.get('timestamp', 'N/A')}<br>"
        hover_text += f"Anomaly Score: {attrs.get('anomaly_score', 0):.2f}"
        node_text.append(hover_text)
        
        # Color by anomaly score
        anomaly_score = attrs.get('anomaly_score', 0)
        if anomaly_score >= 0.8:
            node_color.append('#ff4136')  # Red for critical
        elif anomaly_score >= 0.6:
            node_color.append('#ff851b')  # Orange for high
        elif anomaly_score >= 0.4:
            node_color.append('#ffdc00')  # Yellow for medium
        else:
            node_color.append('#00ff41')  # Green for normal
        
        # Size by degree (number of connections)
        degree = graph.degree(node)
        node_size.append(max(10 + degree * 5, 15))
    
    # Create node trace
    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode='markers+text',
        hoverinfo='text',
        text=[graph.nodes[n].get('action', '')[:10] for n in graph.nodes()],
        textposition="top center",
        textfont=dict(size=8, color='#fafafa'),
        hovertext=node_text,
        marker=dict(
            color=node_color,
            size=node_size,
            line=dict(width=2, color='#fafafa')
        )
    )
    
    # Create figure
    fig = go.Figure(data=[edge_trace, node_trace])
    
    # FIXED: Use proper title syntax for newer Plotly versions
    fig.update_layout(
        title=dict(
            text='Attack Chain Correlation Graph',
            font=dict(size=20, color='#00ff41')
        ),
        showlegend=False,
        hovermode='closest',
        margin=dict(b=20, l=5, r=5, t=40),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#fafafa')
    )
    
    return fig


def create_timeline_chart(chain):
    """
    Create timeline visualization for an attack chain
    
    Args:
        chain: Attack chain dictionary
        
    Returns:
        plotly.graph_objects.Figure: Timeline chart
    """
    events = chain['events']
    
    # Prepare data
    timestamps = [e['timestamp'] for e in events]
    actions = [e['action'] for e in events]
    scores = [e['anomaly_score'] for e in events]
    
    # Create figure
    fig = go.Figure()
    
    # Add timeline trace
    fig.add_trace(go.Scatter(
        x=timestamps,
        y=scores,
        mode='lines+markers',
        name='Anomaly Score',
        line=dict(color='#00ff41', width=2),
        marker=dict(
            size=12,
            color=scores,
            colorscale='RdYlGn_r',
            showscale=True,
            colorbar=dict(title="Anomaly<br>Score")
        ),
        text=actions,
        hovertemplate='<b>%{text}</b><br>Time: %{x}<br>Score: %{y:.2f}<extra></extra>'
    ))
    
    fig.update_layout(
        title=dict(
            text=f'Attack Chain Timeline - {chain["chain_id"]}',
            font=dict(size=18, color='#00ff41')
        ),
        xaxis_title='Time',
        yaxis_title='Anomaly Score',
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#fafafa'),
        hovermode='closest'
    )
    
    return fig


def create_severity_gauge(severity_score):
    """
    Create gauge chart for severity visualization
    
    Args:
        severity_score: Score from 0-1
        
    Returns:
        plotly.graph_objects.Figure: Gauge chart
    """
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=severity_score * 100,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "Threat Level", 'font': {'color': '#fafafa'}},
        gauge={
            'axis': {'range': [None, 100], 'tickcolor': '#fafafa'},
            'bar': {'color': "#00ff41"},
            'steps': [
                {'range': [0, 25], 'color': "#00ff41"},
                {'range': [25, 50], 'color': "#ffdc00"},
                {'range': [50, 75], 'color': "#ff851b"},
                {'range': [75, 100], 'color': "#ff4136"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 80
            }
        }
    ))
    
    fig.update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#fafafa'),
        height=300
    )
    
    return fig


def create_gantt_timeline(timeline_events):
    """
    Create Gantt-style timeline visualization
    
    Args:
        timeline_events: List of timeline event dictionaries
        
    Returns:
        plotly.graph_objects.Figure: Gantt timeline
    """
    if not timeline_events:
        fig = go.Figure()
        fig.add_annotation(
            text="No timeline events to display",
            xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False,
            font=dict(size=20, color='#fafafa')
        )
        fig.update_layout(
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)'
        )
        return fig
    
    # Create Gantt chart data
    fig = go.Figure()
    
    # Group by phase for y-axis
    phases = list(set([e['phase'] for e in timeline_events]))
    phase_to_y = {phase: i for i, phase in enumerate(phases)}
    
    for event in timeline_events:
        # Determine color based on anomaly score
        if event['anomaly_score'] >= 0.8:
            color = '#ff4136'  # Critical
        elif event['anomaly_score'] >= 0.6:
            color = '#ff851b'  # High
        elif event['anomaly_score'] >= 0.4:
            color = '#ffdc00'  # Medium
        else:
            color = event['color']  # Phase color
        
        # Add bar for each event
        duration = event['end'] - event['start']
        # Convert duration to seconds (float) for JSON serialization
        if hasattr(duration, 'total_seconds'):
            duration_val = duration.total_seconds()
        else:
            duration_val = float(duration)
        fig.add_trace(go.Bar(
            x=[duration_val],
            y=[event['phase']],
            base=event['start'],
            orientation='h',
            marker=dict(color=color, line=dict(color='#fafafa', width=1)),
            hovertemplate=(
                f"<b>{event['action']}</b><br>"
                f"Time: {event['start']}<br>"
                f"User: {event['user']}<br>"
                f"IP: {event['ip_address']}<br>"
                f"Phase: {event['phase']}<br>"
                f"Anomaly: {event['anomaly_score']:.2f}<br>"
                f"<extra></extra>"
            ),
            showlegend=False
        ))
    
    fig.update_layout(
        title=dict(
            text='Attack Timeline - Chronological Progression',
            font=dict(size=20, color='#00ff41')
        ),
        xaxis=dict(
            title='Time',
            showgrid=True,
            gridcolor='rgba(255,255,255,0.1)'
        ),
        yaxis=dict(
            title='Kill Chain Phase',
            showgrid=True,
            gridcolor='rgba(255,255,255,0.1)'
        ),
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#fafafa'),
        barmode='overlay',
        height=max(400, len(phases) * 60)
    )
    
    return fig


def create_phase_distribution_chart(phase_distribution):
    """
    Create kill chain phase distribution chart
    
    Args:
        phase_distribution: Dictionary of phase counts
        
    Returns:
        plotly.graph_objects.Figure: Funnel chart
    """
    import plotly.express as px
    
    # Prepare data
    phases = list(phase_distribution.keys())
    counts = list(phase_distribution.values())
    
    # Create funnel chart
    fig = px.funnel(
        y=phases,
        x=counts,
        title='Attack Kill Chain Progression'
    )
    
    fig.update_traces(
        marker=dict(
            color=[
                '#7fdbff', '#0074d9', '#ff851b', '#b10dc9',
                '#ff4136', '#85144b', '#f012be', '#39cccc',
                '#3d9970', '#2ecc40', '#ffdc00', '#ff4136'
            ][:len(phases)]
        )
    )
    
    fig.update_layout(
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#fafafa')
    )
    
    return fig


def create_temporal_heatmap(timeline_df):
    """
    Create temporal heatmap showing activity patterns
    
    Args:
        timeline_df: Timeline DataFrame
        
    Returns:
        plotly.graph_objects.Figure: Heatmap
    """
    import pandas as pd
    
    # Extract hour and day
    timeline_df['hour'] = pd.to_datetime(timeline_df['timestamp']).dt.hour
    timeline_df['date'] = pd.to_datetime(timeline_df['timestamp']).dt.date
    
    # Create pivot table
    heatmap_data = timeline_df.groupby(['date', 'hour']).size().reset_index(name='count')
    heatmap_pivot = heatmap_data.pivot(index='date', columns='hour', values='count').fillna(0)
    
    # Create heatmap
    fig = go.Figure(data=go.Heatmap(
        z=heatmap_pivot.values,
        x=heatmap_pivot.columns,
        y=[str(d) for d in heatmap_pivot.index],
        colorscale='Reds',
        hovertemplate='Date: %{y}<br>Hour: %{x}<br>Events: %{z}<extra></extra>'
    ))
    
    fig.update_layout(
        title=dict(
            text='Temporal Activity Heatmap',
            font=dict(size=18, color='#00ff41')
        ),
        xaxis=dict(title='Hour of Day'),
        yaxis=dict(title='Date'),
        plot_bgcolor='rgba(0,0,0,0)',
        paper_bgcolor='rgba(0,0,0,0)',
        font=dict(color='#fafafa')
    )
    
    return fig