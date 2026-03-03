from flask import Flask, render_template, request
from modules.scanner import scan_network

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/debug-method", methods=["GET", "POST"])
def debug_method():
    # Helpful quick endpoint to see which HTTP method the client used.
    return f"debug-method: {request.method}", 200

@app.route("/scan", methods=["GET", "POST"])
def scan():
    # The endpoint accepts GET and POST so that users don't trigger a
    # 405 error when they type the URL directly or refresh the results.
    #
    # POST: perform the scan and render the results page.
    # GET: simply show the same form as the home page (no scan).
    if request.method == "POST":
        ip_range = request.form.get("ip_range")
        try:
            results = scan_network(ip_range)
            return render_template("results.html", results=results)
        except Exception as e:
            # Pass the error message to the template so the user sees what went wrong
            error = str(e)
            return render_template("results.html", results=[], error=error)

    # GET – render the form again.  Using render_template instead of a
    # redirect keeps the browser on /scan, which is harmless because it
    # doesn't invoke any network activity.  Either approach prevents a
    # Method Not Allowed error.
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)