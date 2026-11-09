
import os
from functools import wraps

from flask import (
    Flask, render_template, request,
    redirect, url_for, session, abort
)
from werkzeug.security import check_password_hash
from dotenv import load_dotenv

from db import get_db_connection

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

if not app.secret_key:
    raise RuntimeError("SECRET_KEY is missing from .env")

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800
)

ROLE_ALIASES = {
    "ADMIN": "SUPER_ADMIN"
}

ROLE_MENUS = {
    "STUDENT": [
        {"id": "overview", "label": "Dashboard", "icon": "⌂", "url": "/dashboard"},
        {"id": "profile", "label": "My Profile", "icon": "◉", "url": "/student/profile"},
        {"id": "events", "label": "Events", "icon": "▦", "url": "/student/events"},
        {"id": "clubs", "label": "Clubs", "icon": "♧", "url": "/student/clubs"},
        {"id": "quizzes", "label": "Quizzes", "icon": "✓", "url": "/student/quizzes"},
        {"id": "feedback", "label": "Feedback", "icon": "✉", "url": "/student/feedback"}
    ],
    "FACULTY": [],
    "HOD": [],
    "OPERATOR": [],
    "SUPER_ADMIN": []
}


def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("home"))
        return function(*args, **kwargs)
    return wrapper


def role_required(*allowed_roles):
    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("home"))

            if session.get("role") not in allowed_roles:
                abort(403)

            return function(*args, **kwargs)
        return wrapper
    return decorator


@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login():
    role = request.form.get("role", "").strip().upper()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not role or not username or not password:
        return render_template("login.html", error="Please fill in all fields.")

    connection = get_db_connection()

    if connection is None:
        return render_template("login.html", error="Database connection failed.")

    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            SELECT user_id, username, password_hash, role,
                   student_id, faculty_id, is_active
            FROM user_accounts
            WHERE username = %s
            LIMIT 1
        """, (username,))

        account = cursor.fetchone()

        if not account:
            return render_template("login.html", error="Invalid username or password.")

        if not account["is_active"]:
            return render_template("login.html", error="Your account is inactive.")

        if not check_password_hash(account["password_hash"], password):
            return render_template("login.html", error="Invalid username or password.")

        actual_role = account["role"].upper()
        actual_role = ROLE_ALIASES.get(actual_role, actual_role)

        if role != actual_role:
            return render_template("login.html", error="Incorrect login role selected.")

        if actual_role not in ROLE_MENUS:
            return render_template("login.html", error="Account role is not configured.")

        session.clear()
        session.permanent = True

        session["user_id"] = account["user_id"]
        session["username"] = account["username"]
        session["role"] = actual_role
        session["student_id"] = account["student_id"]
        session["faculty_id"] = account["faculty_id"]

        return redirect(url_for("dashboard"))

    except Exception:
        app.logger.exception("Login error")
        return render_template("login.html", error="Login failed. Please try again.")

    finally:
        if cursor:
            cursor.close()
        connection.close()


@app.route("/dashboard")
@login_required
def dashboard():
    role = session.get("role")

    templates = {
        "STUDENT": "student_dashboard.html",
        "FACULTY": "faculty_dashboard.html",
        "HOD": "hod_dashboard.html",
        "OPERATOR": "operator_dashboard.html",
        "SUPER_ADMIN": "superadmin_dashboard.html"
    }

    template = templates.get(role)

    if not template:
        abort(403)

    return render_template(
        template,
        page_title=role.replace("_", " ").title(),
        nav_items=ROLE_MENUS[role],
        active_page="overview"
    )


# STUDENT PROFILE

@app.route("/student/profile")
@login_required
@role_required("STUDENT")
def student_profile():
    connection = get_db_connection()

    if connection is None:
        abort(500)

    cursor = None

    try:
        cursor = connection.cursor(dictionary=True)

        cursor.execute("""
            SELECT *
            FROM students
            WHERE student_id = %s
        """, (session.get("student_id"),))

        student = cursor.fetchone()

        return render_template(
            "student_profile.html",
            student=student,
            page_title="My Profile",
            nav_items=ROLE_MENUS["STUDENT"],
            active_page="profile"
        )

    finally:
        if cursor:
            cursor.close()
        connection.close()


# STUDENT EVENTS

@app.route("/student/events")
@login_required
@role_required("STUDENT")
def student_events():
    return render_template(
        "student_events.html",
        page_title="Campus Events",
        nav_items=ROLE_MENUS["STUDENT"],
        active_page="events"
    )


# STUDENT CLUBS

@app.route("/student/clubs")
@login_required
@role_required("STUDENT")
def student_clubs():
    return render_template(
        "student_clubs.html",
        page_title="Student Clubs",
        nav_items=ROLE_MENUS["STUDENT"],
        active_page="clubs"
    )


# STUDENT QUIZZES

@app.route("/student/quizzes")
@login_required
@role_required("STUDENT")
def student_quizzes():
    return render_template(
        "student_quizzes.html",
        page_title="Quizzes",
        nav_items=ROLE_MENUS["STUDENT"],
        active_page="quizzes"
    )


# STUDENT FEEDBACK

@app.route("/student/feedback", methods=["GET", "POST"])
@login_required
@role_required("STUDENT")
def student_feedback():

    if request.method == "POST":
        feedback = request.form.get("feedback", "").strip()

        if not feedback:
            return render_template(
                "student_feedback.html",
                error="Please enter your feedback.",
                page_title="Feedback",
                nav_items=ROLE_MENUS["STUDENT"],
                active_page="feedback"
            )

        # Feedback database insertion will be connected
        # after confirming the feedback table columns.

        return render_template(
            "student_feedback.html",
            success="Thank you for your feedback!",
            page_title="Feedback",
            nav_items=ROLE_MENUS["STUDENT"],
            active_page="feedback"
        )

    return render_template(
        "student_feedback.html",
        page_title="Feedback",
        nav_items=ROLE_MENUS["STUDENT"],
        active_page="feedback"
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.errorhandler(403)
def forbidden(error):
    return render_template(
        "error.html",
        code=403,
        message="You do not have permission to access this page."
    ), 403


if __name__ == "__main__":
    app.run(debug=True)
