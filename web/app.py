"""Flask application factory for PacketTracer Web UI."""

import os
import secrets

from flask import (
    Flask, Blueprint, render_template, redirect, url_for,
    flash, request, session, current_app,
)

from web.auth import (
    auth_bp, init_users_table, close_user_db, get_current_user,
    login_required, admin_required,
)
from web.api import api_bp


def create_app(dashboard=None, config_store=None) -> Flask:
    """Create and configure the Flask application.

    Args:
        dashboard: Running Dashboard instance (shares trackers/db).
        config_store: EncryptedConfigStore instance for settings.
    """
    app = Flask(
        __name__,
        template_folder=os.path.join(os.path.dirname(__file__), "templates"),
        static_folder=os.path.join(os.path.dirname(__file__), "static"),
    )

    # Configuration
    db_path = os.path.expanduser("~/.packettracer/data.db")
    app.config["SECRET_KEY"] = _load_or_generate_secret(db_path)
    app.config["DB_PATH"] = db_path
    app.config["DASHBOARD"] = dashboard
    app.config["CONFIG_STORE"] = config_store

    # Initialize user auth table
    init_users_table(db_path)

    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(main_bp)

    # Teardown
    app.teardown_appcontext(close_user_db)

    # Inject current user into all templates
    @app.context_processor
    def inject_user():
        return {"current_user": get_current_user()}

    return app


def _load_or_generate_secret(db_path: str) -> str:
    """Load or generate the Flask secret key."""
    secret_path = os.path.join(os.path.dirname(db_path), "flask.secret")
    os.makedirs(os.path.dirname(secret_path), exist_ok=True)
    if os.path.exists(secret_path):
        with open(secret_path, "r") as f:
            return f.read().strip()
    secret = secrets.token_hex(32)
    with open(secret_path, "w") as f:
        f.write(secret)
    os.chmod(secret_path, 0o600)
    return secret


# --- Main blueprint (dashboard pages) ---
main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("auth.login"))
    return redirect(url_for("main.dashboard"))


@main_bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@main_bp.route("/flows")
@login_required
def flows():
    return render_template("flows.html")


@main_bp.route("/alerts")
@login_required
def alerts():
    return render_template("alerts.html")


@main_bp.route("/dns")
@login_required
def dns():
    return render_template("dns.html")


@main_bp.route("/anomaly")
@login_required
def anomaly():
    return render_template("anomaly.html")


@main_bp.route("/settings")
@admin_required
def settings():
    store = current_app.config.get("CONFIG_STORE")
    config_keys = store.keys() if store else []
    config_vals = {}
    if store:
        for k in config_keys:
            val = store.get(k)
            # Mask sensitive values in display
            if any(s in k.lower() for s in ("key", "secret", "password", "token")):
                config_vals[k] = "***" + str(val)[-4:] if val else ""
            else:
                config_vals[k] = val
    return render_template("settings.html", config_keys=config_keys, config_vals=config_vals)


@main_bp.route("/settings/update", methods=["POST"])
@admin_required
def update_setting():
    store = current_app.config.get("CONFIG_STORE")
    if not store:
        flash("Config store not available.", "error")
        return redirect(url_for("main.settings"))

    key = request.form.get("key", "").strip()
    value = request.form.get("value", "").strip()

    if not key:
        flash("Key is required.", "error")
    else:
        store.set(key, value)
        flash(f"Setting '{key}' updated.", "success")
    return redirect(url_for("main.settings"))


@main_bp.route("/settings/delete/<key>", methods=["POST"])
@admin_required
def delete_setting(key):
    store = current_app.config.get("CONFIG_STORE")
    if store:
        store.delete(key)
        flash(f"Setting '{key}' deleted.", "success")
    return redirect(url_for("main.settings"))
