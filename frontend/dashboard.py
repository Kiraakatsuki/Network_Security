import dash
from dash import dcc, html, Input, Output
import dash_bootstrap_components as dbc
import plotly.graph_objects as go
from collections import deque
import pandas as pd
from datetime import datetime
import requests

# Initialize Dash app
app = dash.Dash(
    __name__,
    external_stylesheets=[
        dbc.themes.BOOTSTRAP,
        "https://use.fontawesome.com/releases/v5.15.4/css/all.css"
    ],
    meta_tags=[{"name": "viewport", "content": "width=device-width, initial-scale=1.0"}]
)

app.title = "Security OS Dashboard"
server = app.server

# Historical data buffer
traffic_history = deque(maxlen=150)
alert_history = deque(maxlen=5)

# Styling
app.index_string = '''
<!DOCTYPE html>
<html>
<head>
    {%metas%}
    <title>Security OS Dashboard</title>
    {%favicon%}
    {%css%}
    <style>
        body { background-color: #161A30; color: #F0F3F5; font-family: 'Poppins', sans-serif; }
        .card { background: rgba(30,30,45,0.5); border-radius: 1rem; }
        .stat-card-title { font-size: 0.9rem; color: #A9B4CC; text-transform: uppercase; }
        .stat-card-value { font-size: 2.25rem; font-weight: 600; color: #F0F3F5; }
        .stat-card-value.threat { color: #E91E63; }
    </style>
</head>
<body>
    {%app_entry%}
    <footer>
        {%config%}
        {%scripts%}
        {%renderer%}
    </footer>
</body>
</html>
'''

def create_stat_card(title, value_id):
    return dbc.Card(
        dbc.CardBody([
            html.P(title, className="stat-card-title"),
            html.H3(id=value_id, className="stat-card-value")
        ]),
        className="text-start"
    )

# Layout
app.layout = dbc.Container(fluid=True, className="p-4 p-md-5", children=[
    dcc.Interval(id='update-interval', interval=2000, n_intervals=0),

    html.Div([
        html.H1("Security OS", className="fw-bold"),
        html.P(id="current-time", className="text-muted")
    ], className="mb-4"),

    dbc.Row([
        dbc.Col(create_stat_card("Total Traffic", "total-traffic-value"), lg=4, md=6, className="mb-4"),
        dbc.Col(create_stat_card("Threat Level", "threat-level-value"), lg=4, md=6, className="mb-4"),
        dbc.Col(create_stat_card("Active Alerts", "active-alerts-value"), lg=4, md=12, className="mb-4"),
    ]),

    dbc.Row([
        dbc.Col(dbc.Card([
            dbc.CardHeader("Traffic Trend"),
            dbc.CardBody(dcc.Graph(id='traffic-trend-graph', config={'displayModeBar': False}))
        ]), lg=8, className="mb-4"),

        dbc.Col([
            dbc.Card([
                dbc.CardHeader("Traffic Composition"),
                dbc.CardBody(dcc.Graph(id='traffic-composition-pie', config={'displayModeBar': False}, style={'height': '200px'}))
            ], className="mb-4"),
            dbc.Card([
                dbc.CardHeader("Alerts Feed"),
                dbc.CardBody(id='alerts-panel', style={'height': '230px', 'overflowY': 'auto'})
            ])
        ], lg=4, className="mb-4")
    ])
])

@app.callback(
    Output('total-traffic-value', 'children'),
    Output('threat-level-value', 'children'),
    Output('threat-level-value', 'className'),
    Output('active-alerts-value', 'children'),
    Output('traffic-trend-graph', 'figure'),
    Output('traffic-composition-pie', 'figure'),
    Output('alerts-panel', 'children'),
    Output('current-time', 'children'),
    Input('update-interval', 'n_intervals')
)
def update_dashboard(n):
    try:
        response = requests.get("http://localhost:5000/api/live_traffic", timeout=1.5)
        data = response.json()
    except Exception as e:
        print("[ERROR] Could not fetch data from backend:", e)
        return "-", "-", "stat-card-value", "-", {}, {}, html.Div("Connection error"), datetime.now().strftime('%H:%M:%S')

    normal = data.get("normal", 0)
    malicious = data.get("malicious", 0)
    threat = data.get("threat_level", 0.0)
    total = normal + malicious

    traffic_history.append({
        "timestamp": datetime.now(),
        "normal": normal,
        "malicious": malicious
    })

    # Update alerts
    if threat > 0.3:
        alert_msg = f"High threat detected: {malicious} malicious packets"
        alert_history.appendleft({"timestamp": datetime.now(), "message": alert_msg})

    df = pd.DataFrame(list(traffic_history))

    # Trend Graph
    trend_fig = go.Figure()
    trend_fig.add_trace(go.Scatter(x=df['timestamp'], y=df['malicious'], name='Malicious', fill='tozeroy', line=dict(color='#E91E63')))
    trend_fig.add_trace(go.Scatter(x=df['timestamp'], y=df['normal'], name='Normal', fill='tozeroy', line=dict(color='#00BCD4')))
    trend_fig.update_layout(margin=dict(t=20, b=20), paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', height=400)

    # Pie Chart
    pie_fig = go.Figure(data=[go.Pie(
        labels=['Normal', 'Malicious'],
        values=[normal, malicious],
        marker_colors=['#00BCD4', '#E91E63'],
        hole=0.5
    )])
    pie_fig.update_layout(margin=dict(t=0, b=0), height=200, paper_bgcolor='rgba(0,0,0,0)')

    # Alerts Feed
    alerts = html.Div([html.Div([
        html.I(className="fas fa-exclamation-circle text-danger me-2"),
        html.Span(alert['message'], className="me-2"),
        html.Small(alert['timestamp'].strftime('%H:%M:%S'), className="text-muted")
    ], className="d-flex justify-content-between") for alert in alert_history]) if alert_history else html.Div("No active alerts", className="text-muted")

    return (
        f"{total:,}",
        f"{threat*100:.1f}%",
        "stat-card-value threat" if threat > 0.3 else "stat-card-value",
        str(len(alert_history)),
        trend_fig,
        pie_fig,
        alerts,
        datetime.now().strftime('%B %d, %Y • %H:%M:%S')
    )

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8050)
