from flask import Flask, render_template, request
from main import analyze_message, load_memory_from_mysql


app = Flask(__name__)


# Load previous analysis history from MySQL
load_memory_from_mysql()


@app.route("/")
def home():

    return render_template(
        "index.html"
    )


@app.route("/analyze", methods=["POST"])
def analyze():

    message = request.form.get(
        "message",
        ""
    ).strip()

    if not message:

        return render_template(
            "index.html",
            error="Please enter a message."
        )

    result = analyze_message(
        message
    )

    return render_template(
        "index.html",
        result=result,
        message=message
    )


if __name__ == "__main__":

    app.run(
        debug=True
    )