import json
import logging
from datetime import datetime, timedelta, timezone
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

logger = logging.getLogger(__name__)

SCOPES_DRIVE = ["https://www.googleapis.com/auth/drive"]
SCOPES_REPORTS = ["https://www.googleapis.com/auth/admin.reports.audit.readonly"]


class DlpWorkspaceHelper:
    def __init__(
        self,
        service_account_json: dict | str,
        admin_email: str = "soer8596@aaks.dk",
        cooldown_hours: int = 24,
        audit_wait_minutes: int = 60,
    ):
        if isinstance(service_account_json, str) and service_account_json.strip().startswith("{"):
            self.sa_info = json.loads(service_account_json)
        else:
            self.sa_info = service_account_json
            
        self.admin_email = admin_email
        self.cooldown_hours = cooldown_hours
        self.audit_wait_minutes = audit_wait_minutes

    def _get_credentials(self, scopes: list[str], subject: str):
        if isinstance(self.sa_info, dict):
            creds = service_account.Credentials.from_service_account_info(
                self.sa_info, scopes=scopes
            )
        else:
            creds = service_account.Credentials.from_service_account_file(
                self.sa_info, scopes=scopes
            )
        return creds.with_subject(subject)

    def resolve_alert_for_queue(self, alert_payload: dict) -> dict | None:
        """
        Kaldes i Pull-steppet inden workqueue.add_item().
        Returnerer dict klar til item.data, eller None hvis vi afventer Audit Log sync på et Fællesdrev.
        """
        alert_id = alert_payload.get("alertId")
        rule_info = alert_payload.get("data", {}).get("ruleViolationInfo", {})
        res_info = rule_info.get("resourceInfo", {})

        doc_id = res_info.get("documentId")
        doc_title = res_info.get("title", "Ukendt dokument")
        recipients = rule_info.get("recipients", [])
        detectors = sorted(
            [
                d.get("detectorName", "")
                for d in rule_info.get("matchInfo", [])
                if d.get("detectorName")
            ]
        )

        now_utc = datetime.now(timezone.utc)
        alert_time_str = alert_payload.get("createTime")
        alert_dt = (
            datetime.fromisoformat(alert_time_str.replace("Z", "+00:00"))
            if alert_time_str
            else now_utc
        )

        impersonate_target = recipients[0] if recipients else self.admin_email
        actual_user, working_subject = self._find_modifying_user(
            doc_id=doc_id,
            alert_dt=alert_dt,
            impersonate_target=impersonate_target,
            explicit_trigger_user=rule_info.get("triggeringUserEmail"),
        )

        # Opmærksomhedspunkt 1: Håndtering af log-forsinkelse på Shared Drives
        if not actual_user:
            age_minutes = (now_utc - alert_dt).total_seconds() / 60.0
            if age_minutes < self.audit_wait_minutes:
                logger.info(
                    f"Udskyder alarm {alert_id} på '{doc_title}' ({doc_id}) - "
                    f"bruger ikke i Audit Log endnu (alder: {int(age_minutes)} min)."
                )
                return None  # Lægges ikke i køen endnu; prøves igen ved næste kørsel

            actual_user = recipients[0] if recipients else None
            logger.warning(
                f"Kunne ikke finde redaktør efter {int(age_minutes)} min for {doc_id}. "
                f"Falder tilbage til recipient: {actual_user}"
            )

        return {
            "alert_id": alert_id,
            "doc_id": doc_id,
            "doc_title": doc_title,
            "target_user": actual_user,
            "impersonate_subject": working_subject or actual_user or self.admin_email,
            "detectors": detectors,
            "alert_create_time": alert_time_str,
        }

    def is_in_cooldown_or_stamp(self, item_data: dict) -> bool:
        """
        Kaldes i Notify-steppet inde i 'with item:' blokken.
        Returnerer True hvis dokumentet er i 24t karensperiode (springes over for at undgå spam).
        Returnerer False (og stempler filen i Drive) hvis brugeren skal notificeres nu.
        """
        doc_id = item_data["doc_id"]
        subject = item_data.get("impersonate_subject") or item_data["target_user"]
        detectors = set(item_data.get("detectors", []))
        now_utc = datetime.now(timezone.utc)

        try:
            drive_creds = self._get_credentials(SCOPES_DRIVE, subject)
            drive_service = build("drive", "v3", credentials=drive_creds)

            file_meta = (
                drive_service.files()
                .get(fileId=doc_id, supportsAllDrives=True, fields="appProperties")
                .execute()
            )
            app_props = file_meta.get("appProperties", {})
            last_notified_str = app_props.get("dlp_last_notified")
            prev_detectors_str = app_props.get("dlp_detectors", "")

            if last_notified_str:
                last_notified_dt = datetime.fromisoformat(last_notified_str)
                prev_detectors = (
                    set(prev_detectors_str.split(",")) if prev_detectors_str else set()
                )

                # Opmærksomhedspunkt 2: 24 timers karensperiode pr. dokument
                if (now_utc - last_notified_dt) < timedelta(hours=self.cooldown_hours):
                    if detectors.issubset(prev_detectors):
                        logger.info(
                            f"Dokument {doc_id} er i karensperiode (sidst varslet "
                            f"{last_notified_dt.strftime('%Y-%m-%d %H:%M')} UTC). Springer over."
                        )
                        return True

            # Opdater filen med nyt tidsstempel før advisering
            merged_detectors = sorted(
                list(
                    (set(prev_detectors_str.split(",")) if prev_detectors_str else set())
                    | detectors
                )
            )
            drive_service.files().update(
                fileId=doc_id,
                supportsAllDrives=True,
                body={
                    "appProperties": {
                        "dlp_last_notified": now_utc.isoformat(),
                        "dlp_detectors": ",".join(merged_detectors),
                    }
                },
            ).execute()
            return False

        except HttpError as e:
            logger.warning(
                f"Kunne ikke læse/skrive appProperties for {doc_id} via {subject}: {e}. "
                "Fortsætter med advisering."
            )
            return False

    def _find_modifying_user(
        self,
        doc_id: str,
        alert_dt: datetime,
        impersonate_target: str,
        explicit_trigger_user: str | None,
    ) -> tuple[str | None, str | None]:
        if explicit_trigger_user:
            return explicit_trigger_user, explicit_trigger_user

        max_cutoff_dt = alert_dt + timedelta(minutes=2)

        # 1. Prøv Drive API (revisions.list)
        try:
            drive_creds = self._get_credentials(SCOPES_DRIVE, impersonate_target)
            drive_service = build("drive", "v3", credentials=drive_creds)

            revs_response = (
                drive_service.revisions()
                .list(
                    fileId=doc_id,
                    fields="revisions(modifiedTime,lastModifyingUser(emailAddress))",
                    pageSize=20,
                )
                .execute()
            )

            valid_editors = []
            for rev in revs_response.get("revisions", []):
                mod_time_str = rev.get("modifiedTime")
                editor_email = rev.get("lastModifyingUser", {}).get("emailAddress")
                if mod_time_str and editor_email:
                    mod_dt = datetime.fromisoformat(mod_time_str.replace("Z", "+00:00"))
                    if mod_dt <= max_cutoff_dt:
                        valid_editors.append((mod_dt, editor_email))

            if valid_editors:
                valid_editors.sort(key=lambda x: x[0])
                return valid_editors[-1][1], impersonate_target

            file_meta = (
                drive_service.files()
                .get(
                    fileId=doc_id,
                    supportsAllDrives=True,
                    fields="lastModifyingUser(emailAddress)",
                )
                .execute()
            )
            last_editor = file_meta.get("lastModifyingUser", {}).get("emailAddress")
            if last_editor:
                return last_editor, impersonate_target

        except HttpError:
            pass

        # 2. Fallback: Admin SDK Reports API (Drive Audit Log)
        try:
            reports_creds = self._get_credentials(SCOPES_REPORTS, self.admin_email)
            reports_service = build("admin", "reports_v1", credentials=reports_creds)

            start_window = (alert_dt - timedelta(hours=4)).isoformat().replace("+00:00", "Z")
            end_window = max_cutoff_dt.isoformat().replace("+00:00", "Z")

            activities_response = (
                reports_service.activities()
                .list(
                    userKey="all",
                    applicationName="drive",
                    startTime=start_window,
                    endTime=end_window,
                    filters=f"doc_id=={doc_id}",
                    maxResults=15,
                )
                .execute()
            )

            for item in activities_response.get("items", []):
                actor_email = item.get("actor", {}).get("email")
                for event in item.get("events", []):
                    if event.get("name") in ("edit", "create", "upload") and actor_email:
                        return actor_email, actor_email

        except HttpError as e:
            logger.error(f"Reports API opslag fejlede for {doc_id}: {e}")

        return None, None
