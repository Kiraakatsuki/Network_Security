import dash
import dash_bootstrap_components as dbc
import plotly.graph_objs as go
import pandas as pd
import random
from collections import deque
from dash import dcc, html
from dash.dependencies import Input, Output, State
from datetime import datetime, timedelta
import requests

# Initialize the Dash app with Bootstrap
app = dash.Dash(__name__, 
                external_stylesheets=[dbc.themes.BOOTSTRAP],
                meta_tags=[{"name": "viewport", "content": "width=device-width, initial-scale=1"}])

server = app.server  # for deployment

# Traffic Data class with deque for performance
class TrafficData:
    def __init__(self, maxlen=150):  # approx 5 minutes at 2s interval
        self.history = deque(maxlen=maxlen)

    def update(self, normal, malicious, threat_level):
        self.history.append({
            'timestamp': datetime.now(),
            'normal': normal,
            'malicious': malicious,
            'threat_level': threat_level
        })

    def to_dataframe(self):
        return pd.DataFrame(self.history)

# Initialize traffic data
traffic_data = TrafficData()

# Layout
app.layout = html.Div([
    dcc.Store(id='data-store', data={'history': []}),
    dcc.Interval(id='interval-component', interval=2*1000, n_intervals=0),

    dbc.Row([dbc.Col(html.H1('Network Security Dashboard', className="text-center mb-4"), width=12)]),

    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("Real-Time Traffic Monitoring", className="h5"),
                dbc.CardBody([
                    dcc.Graph(id='live-traffic-gauge', config={'displayModeBar': False}),
                    html.Div(id='threat-indicator', className="text-center mt-2")
                ])
            ], className="shadow-sm h-100"),
        ], md=4),

        dbc.Col([
            dbc.Card([
                dbc.CardHeader("Traffic Composition", className="h5"),
                dbc.CardBody([
                    dcc.Graph(id='traffic-composition', config={'displayModeBar': False})
                ])
            ], className="shadow-sm h-100"),
        ], md=4),

        dbc.Col([
            dbc.Card([
                dbc.CardHeader("System Status", className="h5"),
                dbc.CardBody([
                    html.Div([
                        html.Div([
                            html.Span("GPU Acceleration: "),
                            html.Span(id='gpu-status', className="badge")
                        ], className="mb-2"),
                        html.Div([
                            html.Span("Packet Processing: "),
                            html.Span(id='processing-status', className="badge")
                        ], className="mb-2"),
                        html.Div([
                            html.Span("Last Update: "),
                            html.Span(id='last-update', className="text-muted")
                        ])
                    ])
                ])
            ], className="shadow-sm h-100"),
        ], md=4),
    ], className="mb-4"),

    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("Traffic Trend (Last 5 Minutes)", className="h5"),
                dbc.CardBody([
                    dcc.Graph(id='traffic-trend', config={'displayModeBar': False})
                ])
            ], className="shadow-sm"),
        ], width=12),
    ], className="mb-4"),

    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("Recent Security Alerts", className="h5"),
                dbc.CardBody([
                    html.Div(id='alerts-table', className="table-responsive")
                ])
            ], className="shadow-sm"),
        ], width=12),
    ])
], className="container-fluid")

# Callback
@app.callback(
    [Output('live-traffic-gauge', 'figure'),
     Output('traffic-composition', 'figure'),
     Output('traffic-trend', 'figure'),
     Output('threat-indicator', 'children'),
     Output('gpu-status', 'children'),
     Output('processing-status', 'children'),
     Output('last-update', 'children'),
     Output('alerts-table', 'children'),
     Output('data-store', 'data')],
    [Input('interval-component', 'n_intervals')],
    [State('data-store', 'data')]
)
def update_dashboard(n, stored_data):
    try:
        normal = random.randint(50, 200)
        malicious = random.randint(0, 50)
        threat_level = malicious / (normal + malicious + 0.001)

        traffic_data.update(normal, malicious, threat_level)
        df = traffic_data.to_dataframe()

        gpu_status = "Active" if random.random() > 0.1 else "Inactive"
        processing_status = "Normal" if random.random() > 0.1 else "Delayed"

        threat_alert = dbc.Alert("High Threat Level Detected!", color="danger") if threat_level > 0.3 else \
                        dbc.Alert("Moderate Threat Level", color="warning") if threat_level > 0.1 else \
                        dbc.Alert("Normal Operations", color="success")

        gauge_fig = {
            'data': [go.Indicator(
                mode="gauge+number",
                value=threat_level * 100,
                number={"suffix": "%"},
                gauge={
                    'axis': {'range': [0, 100]},
                    'steps': [
                        {'range': [0, 30], 'color': "lightgreen"},
                        {'range': [30, 70], 'color': "orange"},
                        {'range': [70, 100], 'color': "red"}
                    ],
                    'threshold': {
                        'line': {'color': "black", 'width': 4},
                        'thickness': 0.75,
                        'value': threat_level * 100
                    }
                }
            )],
            'layout': go.Layout(title='Current Threat Level', height=250, margin=dict(t=50, b=30, l=30, r=30))
        }

        composition_fig = {
            'data': [go.Pie(
                labels=['Normal Traffic', 'Malicious Traffic'],
                values=[normal, malicious],
                hole=0.4,
                marker=dict(colors=['#28a745', '#dc3545']),
                textinfo='percent+label')],
            'layout': go.Layout(height=250, margin=dict(t=30, b=30, l=30, r=30))
        }

        trend_fig = {
            'data': [
                go.Scatter(x=df['timestamp'], y=df['normal'], mode='lines+markers', name='Normal Traffic', line=dict(color='#28a745')),
                go.Scatter(x=df['timestamp'], y=df['malicious'], mode='lines+markers', name='Malicious Traffic', line=dict(color='#dc3545'))
            ],
            'layout': go.Layout(height=350, xaxis_title='Time', yaxis_title='Packets/sec', margin=dict(t=30, b=50, l=50, r=30), hovermode='x unified')
        }

        alerts = [
            {'time': (datetime.now() - timedelta(seconds=i*10)).strftime('%H:%M:%S'),
             'source': f"192.168.1.{random.randint(1, 50)}",
             'destination': f"10.0.0.{random.randint(1, 10)}",
             'threat': random.choice(['DDoS', 'Port Scan', 'Malware', 'Brute Force']),
             'severity': random.choice(['High', 'Medium', 'Low'])}
            for i in range(5)
        ]

        alerts_table = dbc.Table([
            html.Thead(html.Tr([html.Th(col) for col in ['Time', 'Source', 'Destination', 'Threat Type', 'Severity']])),
            html.Tbody([
                html.Tr([
                    html.Td(alert['time']),
                    html.Td(alert['source']),
                    html.Td(alert['destination']),
                    html.Td(alert['threat']),
                    html.Td(dbc.Badge(alert['severity'], color='danger' if alert['severity']=='High' else 'warning' if alert['severity']=='Medium' else 'success'))
                ]) for alert in alerts
            ])
        ], striped=True, bordered=True, hover=True, responsive=True)

        last_update = datetime.now().strftime('%H:%M:%S')

        stored_data = {
            'history': df.to_dict('records'),
            'last_update': last_update
        }

        return (
            gauge_fig,
            composition_fig,
            trend_fig,
            threat_alert,
            dbc.Badge(gpu_status, color="success" if gpu_status == 'Active' else "danger"),
            dbc.Badge(processing_status, color="success" if processing_status == 'Normal' else "warning"),
            last_update,
            alerts_table,
            stored_data
        )

    except Exception as e:
        print("Error:", e)
        empty_fig = {'data': [], 'layout': {}}
        return (empty_fig, empty_fig, empty_fig,
                dbc.Alert("Connection Error", color="danger"),
                "Error", "Error", "N/A",
                html.Div("No data available"),
                {'history': [], 'last_update': 'N/A'})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8050)
