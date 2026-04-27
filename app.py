import os
import json
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "logs.json")
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w") as f:
        json.dump([], f)
from datetime import datetime
from flask import Flask, render_template, request, jsonify
from detector import analyze_input
import json

app = Flask(__name__)

with open('data/attacks.json', 'r') as f:
    examples = json.load(f)

@app.route("/")
def home():
    try:
        with open(LOG_FILE, "r") as f:
            logs = json.load(f)
    except:
        logs = []

    logs = logs[::-1][:10]  # latest 10 logs

    return render_template("index.html", logs=logs)

@app.route("/analyze", methods=["POST"])
def analyze_route():
    data = request.get_json()
    user_input = data.get("text", "")

    result = analyze_input(user_input)

    log_entry = {
        "input": user_input,
        "verdict": result["verdict"],
        "risk_score": result["risk_score"],
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    with open(LOG_FILE, "r") as f:
        logs = json.load(f)

    logs.append(log_entry)

    with open(LOG_FILE, "w") as f:
        json.dump(logs, f, indent=4)

    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)