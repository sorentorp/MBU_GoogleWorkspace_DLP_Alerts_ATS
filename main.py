import logging
import sys
from automation_server_client import AutomationServer, Credential, WorkItemError
from dlp_helper import DlpWorkspaceHelper
from helpers.get_and_store_alerts import get_alerts_past_week, update_db_with_alerts
from helpers.ats_functions import get_item_info
from helpers import smtp_util
from mbu_dev_shared_components.database.connection import RPAConnection

# Konfigurer logging korrekt
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


def run_pull():
    """Dispatcher: Henter alarmer fra Google Alert Center og fylder ATS-køen via dlp_helper."""
    logger.info("Starter Pull-process (Dispatcher)...")
    
    ats = AutomationServer.from_environment()
    workqueue = ats.workqueue()
    
    # Opret forbindelse til RPA database for at hente konstanter/indstillinger hvis nødvendigt
    rpa_conn = RPAConnection(db_env="PROD", commit=False)
    with rpa_conn:
        app_email = rpa_conn.get_constant("google_dlp_app_email").get("value", "")
        admin_email = rpa_conn.get_constant("google_dlp_admin_email").get("value", "soer8596@aaks.dk")

    # Hent Google Service Account fra ATS Credentials
    google_cred = Credential.get_credential("google_workspace_dlp_service_account")
    dlp_helper = DlpWorkspaceHelper(
        service_account_json=google_cred.password,
        admin_email=admin_email
    )

    # Hent alarmer fra past week (bruger jeres eksisterende funktion)
    past_week_alerts = get_alerts_past_week(app_email=app_email, admin_email=admin_email)
    logger.info(f"Hentet {len(past_week_alerts)} alarmer fra Google Alert API.")

    # Gennemgå alarmer, find den reelle bruger (med hensyntagen til Shared Drive forsinkelse)
    for raw_alert in past_week_alerts:
        alert_id = raw_alert.get("alertId")
        
        # Filtrer kun CPR-relaterede alarmer (ligesom I plejer i queue_handler)
        alert_data = raw_alert.get("data", {})
        if "ruleViolationInfo" not in alert_data:
            continue
        trigger_type = str(alert_data["ruleViolationInfo"].get("ruleInfo", {}).get("displayName", ""))
        if "cpr" not in trigger_type.lower():
            continue

        # Brug dlp_helper til at løse den rigtige bruger og tjekke om den skal udskydes pga. log-forsinkelse
        item_payload = dlp_helper.resolve_alert_for_queue(raw_alert)
        
        if item_payload is None:
            # Afventer Audit Log sync på Fællesdrev – spring over denne gang
            continue
            
        # Tilføj til ATS-køen med alert_id som reference mod dubletter
        workqueue.add_item(data=item_payload, reference=alert_id)
        logger.info(f"Tilføjet alarm {alert_id} til ATS-køen for bruger {item_payload['target_user']}")


def run_notify():
    """Performer: Tømmer ATS-køen, tjekker 24t cooldown og sender adviseringer via smtp_util."""
    logger.info("Starter Notify-process (Performer)...")
    
    ats = AutomationServer.from_environment()
    workqueue = ats.workqueue()
    
    rpa_conn = RPAConnection(db_env="PROD", commit=False)
    with rpa_conn:
        admin_email = rpa_conn.get_constant("google_dlp_admin_email").get("value", "soer8596@aaks.dk")
        email_sender = rpa_conn.get_constant("e-mail_noreply").get("value", "")
        smtp_port = rpa_conn.get_constant("smtp_port").get("value", 25)
        smtp_adm_server = rpa_conn.get_constant("smtp_adm_server").get("value", "")

    google_cred = Credential.get_credential("google_workspace_dlp_service_account")
    dlp_helper = DlpWorkspaceHelper(
        service_account_json=google_cred.password,
        admin_email=admin_email,
        cooldown_hours=24
    )

    body_template = """
    <html>
    <body>
    <p>Kære {to_name},</p>
    <p>Du har uploadet en fil eller tastet et CPR-nummer i en fil i Google-miljøet. Det drejer sig om følgende fil: <a href="{link_to_file}">Link til filen</a>.<br>
    CPR-numre er i kategorien følsomme persondata, som ikke må ligge i Google-miljøet. Du skal derfor sørge for at få flyttet filen.</p>
    <p>Hvis filen indeholder CPR-nummer på en elev, skal den placeres i elevens Digitale mappe i GetOrganized.</p>
    <p>Hvis filen indeholder dit eller din families CPR-nummer, skal filen placeres i OneDrive i en mappe navngivet Privat eller lignende.</p>
    <p><a href="https://intranet.aarhuskommune.dk/documents/128713">Hvis du vil vide mere kan du læse om dette her på AarhusIntra</a></p>
    </body>
    </html>
    """

    for item in workqueue:
        with item:
            data = item.data
            target_user = data.get("target_user")
            doc_title = data.get("doc_title")
            doc_id = data.get("doc_id")
            
            if not target_user:
                raise WorkItemError(f"Ingen modtager fundet for dokument {doc_id} ({doc_title})")
                
            # Tjek 24-timers karensperiode via filens skjulte appProperties i Google Drive
            if dlp_helper.is_in_cooldown_or_stamp(data):
                # Dokumentet er allerede varslet inden for 24 timer -> markeres som 'completed' uden spam.
                continue
                
            # Byg link og send mail vha. jester eksisterende smtp_util
            link_to_file = f"https://drive.google.com/file/d/{doc_id}/view"
            # Hent evt. navn ud fra mailen (eller brug selve mailen som navn hvis ikke oplyst)
            to_name = target_user.split("@")[0].replace(".", " ").title()
            
            body = body_template.format(to_name=to_name, link_to_file=link_to_file)
            
            smtp_util.send_email(
                receiver=target_user,
                sender=email_sender,
                subject="Fil med CPR-nummer i Google Workspace skal flyttes",
                body=body,
                html_body=True,
                smtp_server=smtp_adm_server,
                smtp_port=int(smtp_port)
            )
            logger.info(f"DLP-advarsel sendt succesfuldt til {target_user} vedrørende '{doc_title}'")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "notify":
        run_notify()
    else:
        run_pull()
