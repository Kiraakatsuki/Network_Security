from flask import Flask, render_template
import dash
import dash_core_components as dcc
import dash_html_components as html

app = Flask(__name__)

# Initialize Dash
dash_app = dash.Dash(__name__, server=app, url_base_pathname='/dashboard/')

dash_app.layout = html.Div([
    dcc.Graph(
        id='live-update-graph',
        figure={'data': []}  # Placeholder for dynamic data
    ),
    html.H3('Real-Time Traffic Detection'),
])

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
