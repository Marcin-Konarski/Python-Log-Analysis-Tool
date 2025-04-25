import time
import json
import sys

try:
    import pandas as pd
    import numpy as np
    import dash
    from dash import dcc, html
    from dash.dependencies import Input, Output
    import plotly.graph_objs as go
except ImportError:
    sys.exit("Error: This script requires following modules: pandas, numpy, dash and plotly. Please install with 'pip install pandas numpy dash plotly'")


# Load JSON data
def load_json_data(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

# Convert JSON to DataFrame for easier processing
def json_to_dataframe(json_data):
    events_data = []
    for event in json_data["events"]:
        event_id = event["event_id"]
        occurrences = event["no_occurances"]
        severity = event.get("severity", "Unknown")
        description = event.get("description", "")
        
        # Get source and type from first specific_event (if available)
        specific_events = event.get("specific_events", [])
        if specific_events and isinstance(specific_events, list):
            source = specific_events[0].get("source", "Unknown")
            event_type = specific_events[0].get("event_type", "Unknown")
        else:
            source = "Unknown"
            event_type = "Unknown"
        
        events_data.append({
            "event_id": event_id,
            "occurrences": occurrences,
            "severity": severity,
            "description": description,
            "source": source,
            "type": event_type
        })
    
    return pd.DataFrame(events_data)

# Load data
data = load_json_data("analysis_results.json")
df = json_to_dataframe(data)

# Create Dash app
app = dash.Dash(
    __name__, 
    external_stylesheets=['https://codepen.io/chriddyp/pen/bWLwgP.css'],
    suppress_callback_exceptions=True,
    update_title=None,
    assets_external_path='?v=' + str(int(time.time()))
)

# Get unique values for dropdown options
sources = ['All'] + sorted([src for src in df['source'].unique() if src != 'All'])
event_types = ['All'] + sorted([etype for etype in df['type'].unique() if etype != 'All'])

scrollable_container_style = {
    'height': '400px',
    'overflow-y': 'scroll',
    'border': 'none',
    'border-radius': '15px',
    'padding': '10px',
    'margin': '20px',
    'background-color': 'white',
}

container_style = {
    'background-color': '#f9f9f9',
    'border-radius': '15px',
    'box-shadow': '0 4px 6px rgba(0, 0, 0, 0.1)',
    'padding': '15px 20px',
    'margin-bottom': '15px',
}

text_style = {
    'color': '#333333',
}

app.layout = html.Div([
    html.H3('Windows Event Log Analysis', 
            style={'margin-bottom': '20px', 'color': '#333333', 'text-align': 'center', 'padding-top': '10px'}),

    # Filter section
    html.Div([
        html.Div([
            html.Div([
                # Severity filter
                html.Label('Severity:', 
                        style={'display': 'inline-block', 'margin-right': '10px', 'font-weight': 'bold', 'vertical-align': 'middle', **text_style}),
                dcc.RadioItems(
                    id='severity_filter',
                    options=[
                        {'label': 'All', 'value': 'all'},
                        {'label': 'High', 'value': 'High'},
                        {'label': 'Medium', 'value': 'Medium'},
                        {'label': 'Low', 'value': 'Low'}
                    ],
                    value='all',
                    inline=True,
                    style={'display': 'inline-block', 'vertical-align': 'middle'}
                ),
            ], style={'display': 'inline-block', 'margin-right': '20px'}),
            
            # Scale filter
            html.Div([
                html.Label('Scale:', 
                        style={'display': 'inline-block', 'margin-right': '10px', 'font-weight': 'bold', 'vertical-align': 'middle', **text_style}),
                dcc.RadioItems(
                    id='scale_toggle',
                    options=[
                        {'label': 'Logarithmic', 'value': 'log'},
                        {'label': 'Linear', 'value': 'linear'}
                    ],
                    value='log',
                    inline=True,
                    style={'display': 'inline-block', 'vertical-align': 'middle'}
                ),
            ], style={'display': 'inline-block'}),
        ], style={'margin-bottom': '10px', 'display': 'flex', 'justify-content': 'center'}),

        # Source filter
        html.Div([
            html.Div([
                html.Label('Source:', style={'font-weight': 'bold', 'margin-bottom': '3px', **text_style}),
                dcc.Dropdown(
                    id='source_filter',
                    options=[{'label': source, 'value': source} for source in sources],
                    value='All',
                    clearable=False,
                    style={'width': '100%'},
                    optionHeight=60
                )
            ], style={'width': '200px', 'margin-right': '20px'}),

            # Event type filter
            html.Div([
                html.Label('Event Type:', style={'font-weight': 'bold', 'margin-bottom': '3px', **text_style}),
                dcc.Dropdown(
                    id='type_filter',
                    options=[{'label': etype, 'value': etype} for etype in event_types],
                    value='All',
                    clearable=False,
                    style={'width': '100%'}
                )
            ], style={'width': '200px'})
        ], style={
            'display': 'flex',
            'justify-content': 'center',
            'gap': '10px',
            'position': 'relative',
            'zIndex': 999
        }),
    ], style={
        **container_style, 
        'max-width': '600px',
        'margin': '0 auto'
    }),

    # Scrollable chart container
    html.Div([
        dcc.Graph(
            id='events_chart',
            config={'displayModeBar': 'hover'},
        ),
    ], style=scrollable_container_style),
    
    # Event Count and Active Filters
    html.Div([
        html.Div(id='event-count', style={'text-align': 'left', 'margin-left': '30px', 'font-weight': 'bold', **text_style})
    ], style={'display': 'flex', 'justify-content': 'space-between'})

], style={"max-width": "1200px", "margin": "0 auto", "padding": "0 20px 20px 20px"})

@app.callback(
    [Output('events_chart', 'figure'),
     Output('event-count', 'children'),],
    [Input('severity_filter', 'value'),
     Input('scale_toggle', 'value'),
     Input('source_filter', 'value'),
     Input('type_filter', 'value')]
)
def update_graph(severity_filter, scale_type, source_filter, type_filter):
    # Start with the full dataset
    filtered_df = df.copy()
    
    # Apply filters
    if severity_filter != 'all':
        filtered_df = filtered_df[filtered_df['severity'] == severity_filter]
    
    if source_filter != 'All':
        filtered_df = filtered_df[filtered_df['source'] == source_filter]
    
    if type_filter != 'All':
        filtered_df = filtered_df[filtered_df['type'] == type_filter]
    
    # Sort by occurrences in descending order
    filtered_df = filtered_df.sort_values(by='occurrences', ascending=False)
    
    # Generate hover text with event details
    hover_text = []
    for index, row in filtered_df.iterrows():
        text = f"<b>Event ID:</b> {row['event_id']}<br>"
        text += f"<b>Occurrences:</b> {row['occurrences']}<br>"
        text += f"<b>Source:</b> {row['source']}<br>"
        text += f"<b>Type:</b> {row['type']}<br>"
        if row['severity'] != "Unknown":
            text += f"<b>Severity:</b> {row['severity']}<br>"
        if row['description']:
            text += f"<b>Description:</b> {row['description']}<br>"
        hover_text.append(text)
    
    # Prepare x-values based on scale type
    x_values = filtered_df['occurrences']
    
    if scale_type == 'log':
        x_values = np.log10(filtered_df['occurrences'] + 1)
        x_axis_title = 'Number of Occurrences (Log Scale)'
    else:
        x_axis_title = 'Number of Occurrences'
    
    # Create bar chart
    fig = go.Figure(data=[
        go.Bar(
            x=x_values,
            y=[f"Event ID: {id}" for id in filtered_df['event_id']],
            text=filtered_df['occurrences'],
            textposition='auto',
            textangle=0,
            marker=dict(
                color=[
                    '#ffb919' if sev == 'High' else
                    '#f1b3a9' if sev == 'Medium' else
                    '#008779' if sev == 'Low' else
                    '#c0eefa'
                    for sev in filtered_df['severity']
                ]
            ),
            orientation='h',
            hoverinfo='text',
            hovertext=hover_text,
            width=0.7
        )
    ])
    
    # Calculate height based on total events
    bar_height = 30
    padding = 100
    chart_height = max(200, len(filtered_df) * bar_height + padding)
    
    # Configure the layout
    fig.update_layout(
        plot_bgcolor='#F2F2F2',
        paper_bgcolor='#FFF',
        title={
            'text': "Event Log Analysis",
            'y': 0.98,
            'x': 0.5,
            'xanchor': 'center',
            'yanchor': 'top'
        },
        hovermode='closest',
        margin=dict(l=150, r=50, t=70, b=50),
        height=chart_height,
        yaxis={
            'autorange': 'reversed',
            'showgrid': False,
            'zeroline': False,
        },
        xaxis={
            'title': x_axis_title,
            'showgrid': True,
            'tickvals': [0, 1, 2, 3, 4, 5] if scale_type == 'log' else None,
            'ticktext': ['0', '10', '100', '1K', '10K', '100K'] if scale_type == 'log' else None
        }
    )
    
    total_events = filtered_df['occurrences'].sum()
    event_count_text = f"Total Event IDs: {len(filtered_df)}. Total Events: {total_events}"

    if len(filtered_df) == 0:
        fig = go.Figure()
        fig.update_layout(
            xaxis={"visible": False},
            yaxis={"visible": False},
            plot_bgcolor='rgba(0,0,0,0)',  # Transparent plot background
            paper_bgcolor='rgba(0,0,0,0)',  # Transparent paper background
            annotations=[{
                "text": "No events match the selected filters.<br>Please try different filter settings.",
                "xref": "paper",
                "yref": "paper",
                "showarrow": False,
                "font": {"size": 20, "color": "#333333"},
                "x": 0.5,
                "y": 0.5,
                "xanchor": "center",
                "yanchor": "middle",
                "bgcolor": "rgba(0,0,0,0)",  # Transparent annotation background
                "bordercolor": "rgba(0,0,0,0)"  # No border
            }],
            margin=dict(l=20, r=20, t=70, b=20),
            height=300
        )
        return fig, ""

    return fig, event_count_text

if __name__ == '__main__':
    app.run(debug=True)