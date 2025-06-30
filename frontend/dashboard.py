import dash
import dash_bootstrap_components as dbc
import plotly.graph_objs as go
import pandas as pd
from collections import deque
from dash import dcc, html
from dash.dependencies import Input, Output, State
from datetime import datetime, timedelta
import requests

# Initialize Dash app with Bootstrap theme
app = dash.Dash(__name__, 
                external_stylesheets=[dbc.themes.BOOTSTRAP],
                meta_tags=[{"name": "viewport", "content": "width=device-width, initial-scale=1"}])

server = app.server  # WSGI entry point for deployment

class TrafficData:
    def __init__(self, maxlen=150):
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

traffic_data = TrafficData()

app.layout = html.Div([
    dcc.Store(id='data-store', data={'history': []}),
    dcc.Interval(id='interval-component', interval=2000, n_intervals=0),

    dbc.Row([dbc.Col(html.H1('Network Security Dashboard', className="text-center mb-4"), width=12)]),

    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("Real-Time Traffic Monitoring"),
                dbc.CardBody([
                    dcc.Graph(id='live-traffic-gauge', config={'displayModeBar': False}),
                    html.Div(id='threat-indicator', className="text-center mt-2")
                ])
            ])
        ], md=4),
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("Traffic Composition"),
                dbc.CardBody([
                    dcc.Graph(id='traffic-composition', config={'displayModeBar': False})
                ])
            ])
        ], md=4),
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("System Status"),
                dbc.CardBody([
                    html.Div([
                        html.Div([html.Span("GPU Acceleration: "), html.Span(id='gpu-status', className="badge")]),
                        html.Div([html.Span("Packet Processing: "), html.Span(id='processing-status', className="badge")]),
                        html.Div([html.Span("Last Update: "), html.Span(id='last-update', className="text-muted")])
                    ])
                ])
            ])
        ], md=4)
    ], className="mb-4"),

    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("Traffic Trend (Last 5 Minutes)"),
                dbc.CardBody([
                    dcc.Graph(id='traffic-trend', config={'displayModeBar': False})
                ])
            ])
        ], width=12)
    ], className="mb-4"),

    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("Recent Security Alerts"),
                dbc.CardBody([
                    html.Div(id='alerts-table', className="table-responsive")
                ])
            ])
        ], width=12)
    ])
], className="container-fluid")

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
        res = requests.get('http://localhost:5000/api/live_traffic')
        res.raise_for_status()
        data = res.json()

        normal = data.get("normal", 0)
        malicious = data.get("malicious", 0)
        threat_level = data.get("threat_level", 0)

        traffic_data.update(normal, malicious, threat_level)
        df = traffic_data.to_dataframe()

        gauge_fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=threat_level * 100,
            number={"suffix": "%"},
            gauge={
                'axis': {'range': [0, 100]},
                'steps': [
                    {'range': [0, 30], 'color': "lightgreen"},
                    {'range': [30, 70], 'color': "orange"},
                    {'range': [70, 100], 'color': "red"}
                ]
            }
        ))
        gauge_fig.update_layout(title='Current Threat Level', height=250, margin=dict(t=30, b=30, l=30, r=30))

        composition_fig = go.Figure(data=[go.Pie(
            labels=['Normal Traffic', 'Malicious Traffic'],
            values=[normal, malicious],
            hole=0.4,
            marker=dict(colors=['#28a745', '#dc3545'])
        )])
        composition_fig.update_layout(height=250, margin=dict(t=30, b=30, l=30, r=30))

        trend_fig = go.Figure()
        trend_fig.add_trace(go.Scatter(x=df['timestamp'], y=df['normal'], mode='lines+markers', name='Normal Traffic', line=dict(color='#28a745')))
        trend_fig.add_trace(go.Scatter(x=df['timestamp'], y=df['malicious'], mode='lines+markers', name='Malicious Traffic', line=dict(color='#dc3545')))
        trend_fig.update_layout(height=350, xaxis_title='Time', yaxis_title='Packets/sec', hovermode='x unified', margin=dict(t=30, b=50))

        alert_color = "success" if threat_level < 0.1 else "warning" if threat_level < 0.3 else "danger"
        alert_msg = "Normal Operations" if alert_color == "success" else "Moderate Threat Level" if alert_color == "warning" else "High Threat Level Detected!"
        threat_alert = dbc.Alert(alert_msg, color=alert_color)

        alerts_table = html.Div("Live packet preview and flags: src_port={} dst_port={} flags={}".format(
            data.get("src_port"), data.get("dst_port"), data.get("flags")
        ))

        gpu_status = dbc.Badge(data.get("gpu", "Inactive"), color="success" if data.get("gpu") == "Active" else "danger")
        processing_status = dbc.Badge(data.get("processing", "Unknown"), color="success" if data.get("processing") == "Normal" else "warning")

        last_update = data.get("timestamp", "N/A")

        stored_data = {'history': df.to_dict('records'), 'last_update': last_update}

        return gauge_fig, composition_fig, trend_fig, threat_alert, gpu_status, processing_status, last_update, alerts_table, stored_data

    except Exception as e:
        print("[ERROR] update_dashboard():", e)
        return ({'data': [], 'layout': {}},) * 3 + [
            dbc.Alert("Connection Error", color="danger"),
            "Error", "Error", "N/A", html.Div("No data available"), {'history': [], 'last_update': 'N/A'}
        ]

if __name__ == '__main__':
    app.run(debug=True, port=8050, host="0.0.0.0")
