import time
import json
import sys

try:
    import pandas as pd # type: ignore
    import numpy as np # type: ignore
    import dash # type: ignore
    from dash import dcc, html, ctx # type: ignore
    from dash.dependencies import Input, Output, State # type: ignore
    import plotly.graph_objs as go # type: ignore
except ImportError:
    sys.exit("Error: This script requires following modules: pandas, numpy, dash and plotly. Please install with 'pip install pandas numpy dash plotly'")

import mysql.connector

def load_data_from_mysql():
    conn = mysql.connector.connect(
        host="192.168.57.130",
        port=3306,
        user="LU",
        password="1111",
        database="event_logs"
    )
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT event_id, event_type, source, date, message FROM logs")
    rows = cursor.fetchall()
    df = pd.DataFrame(rows)
    df['date'] = pd.to_datetime(df['date'], errors='coerce')
    return df

df = load_data_from_mysql()
    
# Convert JSON to DataFrame for easier processing
def json_to_dataframe(json_data):
    events_data = []
    for event in json_data["events"]:
        specific_events = event.get("specific_events", [])
        
        if specific_events and isinstance(specific_events, list):
            for specific_event in specific_events:
                events_data.append({
                    "event_id": specific_event.get("event_id", "Unknown"),
                    "occurrences": event.get("no_occurances", 0),
                    "severity": specific_event.get("event_type", "Unknown"),  # Używamy event_type jako severity
                    "description": "",  # Brak opisu w danych wejściowych
                    "source": specific_event.get("source", "Unknown"),
                    "event_type": specific_event.get("event_type", "Unknown"),
                    "date": specific_event.get("date", "Unknown"),
                    "message": specific_event.get("message", "")
                })
    
    return pd.DataFrame(events_data)

# Load data
# data = load_json_data("analysis_results.json")
# df = json_to_dataframe(data)


# Create Dash app
app = dash.Dash(
    __name__, 
    external_stylesheets=['https://codepen.io/chriddyp/pen/bWLwgP.css'],
    suppress_callback_exceptions=True,
    update_title=None,
    assets_external_path='?v=' + str(int(time.time()))
)

# Get unique values for dropdown options
sources = ['All'] + sorted([src for src in df['source'].unique() if src != 'Unknown' and src != 'All'])
event_types = ['All'] + sorted([etype for etype in df['event_type'].unique() if etype != 'Unknown' and etype != 'All'])

scrollable_container_style = {
    'height': '500px',
    'overflow-y': 'auto',
    'border': 'none',
    'border-radius': '15px',
    'padding': '30px',
    'margin': '25px',
    'background-color': 'white',
}

container_style = {
    'background-color': '#f9f9f9',
    'border-radius': '5px',
    'box-shadow': '0 4px 6px rgba(0, 0, 0, 0.1)',
    'padding': '10px 15px',
    'margin-bottom': '10px',
}

text_style = {
    'color': '#333333',
}

pagination_style = {
    'display': 'flex',
    'justify-content': 'center',
    'align-items': 'center',
    'margin': '10px 0',
}

app.layout = html.Div([
    html.H3('Windows Event Log Viewer',
            style={'margin-bottom': '10px', 'color': '#333333', 'text-align': 'center', 'padding-top': '0px'}),

    html.Div([
        #Source filter
        html.Div([
            html.Label('Source:', style={'font-weight': 'bold', **text_style}),
            dcc.Dropdown(
                id='source_filter',
                options=[{'label': source, 'value': source} for source in sources],
                value='All',
                clearable=False
            )
        ], style={'width': '200px', 'margin-right': '20px'}),

        #Type filter
        html.Div([
            html.Label('Event Type:', style={'font-weight': 'bold', **text_style}),
            dcc.Dropdown(
                id='type_filter',
                options=[{'label': etype, 'value': etype} for etype in event_types],
                value='All',
                clearable=False
            )
        ], style={'width': '200px', 'margin-right': '20px'}),
        
        #ID Search
        html.Div([
            html.Label('Event ID:', style={'font-weight': 'bold', **text_style}),
            dcc.Input(id='event_id_filter', type='text', placeholder='np. 4624', debounce=True)
        ], style={'margin-right': '20px'}),
        
        # Date filter
        html.Div([
            html.Label('Date Range:', style={'font-weight': 'bold', **text_style}),
            dcc.DatePickerRange(
                id='date_range',
                start_date_placeholder_text="Start Date",
                end_date_placeholder_text="End Date",
                display_format='YYYY-MM-DD',
                minimum_nights=0,
                clearable=True,
            ),
        ], style={'margin-right': '20px'}),

        html.Div([
            html.Label('Start Time (HH:MM):', style={'font-weight': 'bold', **text_style}),
            dcc.Input(id='start_time', type='text', placeholder='13:00', debounce=True)
        ], style={'margin-right': '20px'}),

        html.Div([
            html.Label('End Time (HH:MM):', style={'font-weight': 'bold', **text_style}),
            dcc.Input(id='end_time', type='text', placeholder='17:00', debounce=True)
        ]),

    ], style={'display': 'flex', 'justify-content': 'center', 'flex-wrap': 'wrap', 'gap': '15px'}),

    html.Div(id='logs_container', style=scrollable_container_style),
    
    html.Div([
        html.Button('Previous', id='prev_page', n_clicks=0, 
                   style={'margin-right': '10px', 'padding': '5px 15px'}),
        html.Span(id='page_info', style={'margin': '0 10px'}),
        html.Button('Next', id='next_page', n_clicks=0,
                   style={'margin-left': '10px', 'padding': '5px 15px'})
    ], style=pagination_style),

    dcc.Store(id='filtered_logs_store'),
    dcc.Store(id='page_store', data=0)
], style={'max-width': '1000px', 'margin': '0 auto', 'padding': '10px'})

@app.callback(
    Output('filtered_logs_store', 'data'),
    Output('page_store', 'data'),
    Input('source_filter', 'value'),
    Input('type_filter', 'value'),
    Input('date_range', 'start_date'),
    Input('date_range', 'end_date'),
    Input('start_time', 'value'),
    Input('end_time', 'value'),
    Input('event_id_filter', 'value'),
    Input('prev_page', 'n_clicks'),
    Input('next_page', 'n_clicks'),
    State('filtered_logs_store', 'data'),
    State('page_store', 'data')
)
def update_logs_and_page(source, event_type, start_date, end_date, start_time, end_time, event_id, prev_clicks, next_clicks, stored_logs, current_page):
    ctx = dash.callback_context
    triggered_id = ctx.triggered[0]['prop_id'].split('.')[0] if ctx.triggered else None

    # Jeśli zmieniono filtr
    if triggered_id in {'source_filter', 'type_filter', 'date_range', 'start_time', 'end_time', 'event_id_filter'}:
        filtered_df = df.copy()

        if source != 'All':
            filtered_df = filtered_df[filtered_df['source'] == source]
        if event_type != 'All':
            filtered_df = filtered_df[filtered_df['event_type'] == event_type]
        if event_id:
            filtered_df = filtered_df[filtered_df['event_id'].astype(str).str.contains(event_id.strip(), case=False, na=False)]

        try:
            if start_date:
                start_str = f"{start_date} {start_time or '00:00'}"
                start_dt = pd.to_datetime(start_str, errors='coerce')
                filtered_df = filtered_df[filtered_df['date'] >= start_dt]
            if end_date:
                end_str = f"{end_date} {end_time or '23:59'}"
                end_dt = pd.to_datetime(end_str, errors='coerce')
                filtered_df = filtered_df[filtered_df['date'] <= end_dt]
        except Exception:
            pass
        

        filtered_df = filtered_df.sort_values(by='date', ascending=False)
        return filtered_df.to_dict('records'), 0

    # Jeśli kliknięto przyciski stronicowania
    elif triggered_id in {'prev_page', 'next_page'} and stored_logs is not None:
        total_pages = max((len(stored_logs) - 1) // 25 + 1, 1)

        if triggered_id == 'prev_page' and current_page > 0:
            return stored_logs, current_page - 1
        elif triggered_id == 'next_page' and (current_page + 1) * 25 < len(stored_logs):
            return stored_logs, current_page + 1
        else:
            return stored_logs, current_page

    # Pierwsze ładowanie - zwróć pełne dane
    if stored_logs is None:
        filtered_df = df.sort_values(by='date', ascending=False)
        return filtered_df.to_dict('records'), 0

    return stored_logs, current_page

@app.callback(
    Output('logs_container', 'children'),
    Output('page_info', 'children'),
    Input('filtered_logs_store', 'data'),
    Input('page_store', 'data')
)
def update_display(logs_data, page):
    if not logs_data:
        return html.Div("No logs found."), ""

    start = page * 25
    end = start + 25
    page_logs = logs_data[start:end]

    log_elements = []
    current_date = None
    
    for log in page_logs:
        # Pobierz typ eventu i ustaw odpowiedni kolor tła
        event_type = log.get('event_type', '')
        if 'ERROR' in event_type:
            bg_color = '#FFAACF'  # jasny czerwony
        elif 'WARNING' in event_type:
            bg_color = '#fff8e1'  # jasny żółty
        elif 'INFORMATION' in event_type or 'info' in event_type:
            bg_color = '#e3f2fd'  # jasny niebieski
        else:
            bg_color = 'white'  # domyślny kolor
        
        # Pobierz datę z loga i sformatuj tylko część daty (bez czasu)
        log_date = log.get('date', '')
        try:
            if isinstance(log_date, str):
                date_obj = pd.to_datetime(log_date, errors='coerce')
                display_date = date_obj.strftime('%Y-%m-%d') if not pd.isna(date_obj) else 'Unknown date'
            else:
                display_date = log_date.strftime('%Y-%m-%d')
        except:
            display_date = 'Unknown date'
        
        # Jeśli data się zmieniła, dodaj nagłówek z datą
        if display_date != current_date:
            log_elements.append(html.Div(
                display_date,
                style={
                    'background-color': '#e0e0e0',
                    'padding': '15px',
                    'margin': '5px 0 5px 0',
                    'border-radius': '5px',
                    'font-weight': 'bold',
                    'text-align': 'center',
                    'box-shadow': '0 2px 3px rgba(0,0,0,0.1)'
                }
            ))
            current_date = display_date
            
        date_str = log.get('date', '')
        if isinstance(date_str, str):
            pass
        else:
            try:
                date_str = date_str.strftime('%Y-%m-%d %H:%M:%S')
            except:
                date_str = str(date_str)
        
        message_full = log.get('message', '')
        message_preview = message_full[:1000] + ('...' if len(message_full) > 1000 else '')

        log_elements.append(html.Div([
            html.P(f"Time: {date_str.split('T')[1] if 'T' in date_str else 'Unknown'}", 
                style={'margin': '0', 'font-weight': 'bold', 'color': '#555'}),
            html.P(f"Source: {log.get('source', 'Unknown')}", style={'margin': '0'}),
            html.P(f"Type: {log.get('event_type', 'Unknown')}", style={'margin': '0'}),
            html.P(f"Event ID: {log.get('event_id', 'Unknown')}", style={'margin': '0'}),

            html.Details([
                html.Summary("Message:", style={'cursor': 'pointer', 'margin-top': '5px'}),
                html.Div(message_full, style={'white-space': 'pre-wrap', 'margin-top': '5px'})
            ]) if len(message_full) > 1000 else
            html.P(f"Message: {message_full}", style={'margin': '0', 'white-space': 'pre-wrap', 'margin-top': '5px'})
        ], style={
            **container_style,
            'background-color': bg_color,
        }))

    total_pages = max((len(logs_data) - 1) // 25 + 1, 1)
    page_text = f"Page {page + 1} of {total_pages}"

    return log_elements, page_text


if __name__ == '__main__':
    app.run(debug=True)