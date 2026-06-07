from flask import Flask
from flask import render_template
from flask import jsonify
from flask import send_file

import threading

from packet_sniffer import (
    packets_data,
    start_sniffing
)

app = Flask(__name__)

capture_started = False

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/start")
def start():

    global capture_started

    if not capture_started:

        capture_started = True

        thread = threading.Thread(
            target=start_sniffing
        )

        thread.daemon = True
        thread.start()

    return jsonify({
        "status": "started"
    })

@app.route("/packets")
def packets():

    return jsonify(
        packets_data[-100:]
    )

@app.route("/download")
def download():

    return send_file(
        "captures/packets.csv",
        as_attachment=True
    )

if __name__ == "__main__":
    app.run(
        debug=True,
        port=5000
    )