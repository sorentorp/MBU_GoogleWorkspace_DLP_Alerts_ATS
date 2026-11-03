import logging
import sys
from automation_server_client import AutomationServer, Credential, WorkItemError
from dlp_helper import DlpWorkspaceHelper

# Konfigurer logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


def run_pull():
    """Dispatcher: Henter alarmer fra Google Alert Center og fylder ATS-køen."""
    logger.info("Starter Pull-process (Dispatcher)...")
    
    ats = AutomationServer.from_environment()
    workqueue = ats.workqueue()
    
    # Hent Google Service Account fra ATS Credentials
    google_cred = Credential.get_credential("google_workspace_dlp_service_account")
    dlp_helper = DlpWorkspaceHelper(
        service_account_json=google_cred.password,
        admin_email="soer8596@aaks.dk"
    )

    # 1. Hent rå alarmer fra jeres eksisterende funktion
    fetched_alerts_from_google = fetch_alerts_from_google_api()

    # 2. Gennemgå alarmer, slå bruger op og tjek for log-forsinkelse på Shared Drives
    for raw_alert in fetched_alerts_from_google:
        alert_id = raw_alert.get("alertId")
        
        item_payload = dlp_helper.resolve_alert_for_queue(raw_alert)
        
        if item_payload is None:
            # Brugeren er ikke synkroniseret til Audit Log endnu – spring over og prøv igen næste gang
            continue
            
        # Tilføj til ATS-køen med alert_id som reference mod dubletter
        workqueue.add_item(data=item_payload, reference=alert_id)
        logger.info(f"Tilføjet alarm {alert_id} til køen for bruger {item_payload['target_user']}")


def run_notify():
    """Performer: Tømmer ATS-køen, tjekker 24t cooldown og sender adviseringer."""
    logger.info("Starter Notify-process (Performer)...")
    
    ats = AutomationServer.from_environment()
    workqueue = ats.workqueue()
    
    google_cred = Credential.get_credential("google_workspace_dlp_service_account")
    dlp_helper = DlpWorkspaceHelper(
        service_account_json=google_cred.password,
        admin_email="soer8596@aaks.dk",
        cooldown_hours=24
    )

    for item in workqueue:
        with item:
            data = item.data
            target_user = data.get("target_user")
            doc_title = data.get("doc_title")
            doc_id = data.get("doc_id")
            
            if not target_user:
                raise WorkItemError(f"Ingen modtager fundet for dokument {doc_id} ({doc_title})")
                
            # Tjek 24-timers karensperiode via filens skjulte appProperties
            if dlp_helper.is_in_cooldown_or_stamp(data):
                # Dokumentet er allerede varslet inden for 24 timer. 
                # Markeres automatisk som 'completed' i ATS uden at spamme brugeren.
                continue
                
            # Send advisering til den reelle bruger, der indtastede dataene
            send_dlp_warning_email(
                to_email=target_user,
                doc_title=doc_title,
                doc_id=doc_id,
                detectors=data.get("detectors", [])
            )
            logger.info(f"DLP-advarsel sendt succesfuldt til {target_user} vedrørende '{doc_title}'")


if __name__ == "__main__":
    # ATS/Python-standard: Vælg funktion baseret på argument (eller kør pull som standard, 
    # afhængigt af hvordan I opretter robotterne i Automation Server)
    if len(sys.argv) > 1 and sys.argv[1] == "notify":
        run_notify()
    else:
        run_pull()
