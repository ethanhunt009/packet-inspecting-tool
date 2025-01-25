import dash
from dash import dcc, html, dash_table, Input, Output, State
import plotly.graph_objs as go
from datetime import datetime
import threading
import time
import json

# Shared data structure for threat storage
threats = []
lock = threading.Lock()

# Initialize Dash app
app = dash.Dash(__name__)
app.title = "Network Threat Dashboard"

app.layout = html.Div([
    html.H1("Network Threat Monitoring Dashboard", style={'textAlign': 'center'}),
    
    dcc.Interval(id='update-interval', interval=1*1000),
    
    html.Div([
        html.Div([
            html.H3("Live Threats", className="card-title"),
            dash_table.DataTable(
                id='threat-table',
                columns=[
                    {'name': 'Timestamp', 'id': 'timestamp'},
                    {'name': 'Source IP', 'id': 'source_ip'},
                    {'name': 'Threat Type', 'id': 'threat_type'},
                    {'name': 'Details', 'id': 'details'}
                ],
                style_table={'height': '400px', 'overflowY': 'auto'},
                style_cell={'textAlign': 'left', 'padding': '10px'},
                style_header={'backgroundColor': '#003366', 'color': 'white'}
            )
        ], className="six columns"),
        
        html.Div([
            html.H3("Threat Statistics", className="card-title"),
            dcc.Graph(id='threat-pie'),
            html.Button('Block Selected', id='block-button', n_clicks=0,
                       style={'marginTop': '20px', 'backgroundColor': '#ff4444'})
        ], className="six columns")
    ], className="row"),
    
    html.Div(id='hidden-div', style={'display': 'none'})
], style={'padding': '20px'})

@app.callback(
    [Output('threat-table', 'data'),
     Output('threat-pie', 'figure')],
    [Input('update-interval', 'n_intervals')]
)
def update_dashboard(_):
    with lock:
        current_threats = threats[-100:]  # Show last 100 threats
        
    # Create pie chart data
    threat_counts = {}
    for t in current_threats:
        threat_type = t.get('threat_type', 'Unknown')
        threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
        
    pie_fig = {
        'data': [go.Pie(
            labels=list(threat_counts.keys()),
            values=list(threat_counts.values()),
            hole=.3
        )],
        'layout': go.Layout(
            margin={'l': 30, 'r': 30, 't': 30, 'b': 30},
            showlegend=True
        )
    }
    
    return current_threats, pie_fig

@app.callback(
    Output('hidden-div', 'children'),
    [Input('block-button', 'n_clicks')],
    [State('threat-table', 'selected_rows'),
     State('threat-table', 'data')]
)
def block_selected(n_clicks, selected_rows, data):
    if n_clicks > 0 and selected_rows:
        selected_items = [data[i] for i in selected_rows]
        for item in selected_items:
            print(f"Blocking {item.get('source_ip', 'Unknown IP')}")  # Add actual blocking logic
        return f"Blocked {len(selected_items)} threats"
    return ""

def run_dashboard():
    app.run_server(port=8051, debug=False)

def add_threat(threat_data):
    with lock:
        threats.append({
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            **threat_data
        })

if __name__ == '__main__':
    run_dashboard()