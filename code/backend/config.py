from __future__ import annotations

MAX_UPLOAD_BYTES = 250 * 1024 * 1024
MAX_STAGES = 15
DEFAULT_CLUSTER_SECONDS = 120
STORY_MERGE_SECONDS = 120

COLUMN_ALIASES = {
    "timestamp": [
        "datetime", "timestamp", "event_time", "occurred_at", "created_at",
        "time_created", "date_time", "date", "time", "@timestamp"
    ],
    "event_id": ["event_id", "eventid", "event_code", "eventcode", "id_event", "win_event_id"],
    "computer": [
        "computer_name", "hostname", "host", "computer", "device_name",
        "device", "machine", "endpoint", "asset", "dest_host", "destination_host"
    ],
    "source_host": [
        "source_host", "src_host", "client_host", "origin_host", "workstation",
        "workstation_name", "source_hostname"
    ],
    "target_host": [
        "target_host", "dest_host", "destination_host", "server", "remote_host",
        "target", "resource_host"
    ],
    "user": [
        "user_sid", "username", "user_name", "user", "account_name", "account",
        "subject_user_name", "principal", "identity", "actor", "initiated_by"
    ],
    "source": [
        "source_name", "provider_name", "provider", "source", "channel",
        "log_name", "product", "service", "sensor"
    ],
    "source_ip": [
        "source_ip", "src_ip", "client_ip", "remote_ip", "ip_address",
        "origin_ip", "client_address"
    ],
    "target_ip": [
        "target_ip", "dst_ip", "dest_ip", "destination_ip", "server_ip",
        "remote_address"
    ],
    "action": [
        "action", "activity", "event_type", "type", "category", "operation",
        "task", "status", "verb", "activity_type"
    ],
    "result": [
        "result", "outcome", "status", "success", "decision", "response",
        "event_outcome"
    ],
    "message": [
        "message", "description", "details", "detail", "event_message",
        "raw_message", "log", "command_line", "command", "query"
    ],
    "object": [
        "object", "object_name", "file", "file_name", "filename", "path",
        "resource", "target_object", "share_name", "url", "uri"
    ],
    "bytes_out": [
        "bytes_out", "outbound_bytes", "bytes_sent", "sent_bytes",
        "upload_bytes", "tx_bytes"
    ],
    "bytes_in": [
        "bytes_in", "inbound_bytes", "bytes_received", "received_bytes",
        "download_bytes", "rx_bytes"
    ],
}

# Windows IDs are OPTIONAL structured evidence. They add confidence when present;
# they are never required for classification.
WINDOWS_EVENT_HINTS = {
    "1102": ("defence_evasion", 0.25, "Windows audit log clear event"),
    "4624": ("authentication_success", 0.20, "Windows successful logon event"),
    "4625": ("access_declined", 0.20, "Windows failed logon event"),
    "4634": ("session_exit", 0.20, "Windows logoff event"),
    "4648": ("credential_use", 0.18, "Windows explicit credential event"),
    "4672": ("privileged_session", 0.22, "Windows special privileges event"),
    "4688": ("hacking_activity", 0.15, "Windows process creation event"),
    "4697": ("service_installation", 0.22, "Windows service installation event"),
    "4720": ("account_management", 0.22, "Windows account creation event"),
    "4722": ("account_management", 0.20, "Windows account enable event"),
    "4724": ("account_management", 0.20, "Windows password reset event"),
    "4728": ("security_group_modification", 0.22, "Windows global group membership event"),
    "4732": ("security_group_modification", 0.22, "Windows local group membership event"),
    "4771": ("access_declined", 0.18, "Windows Kerberos pre-authentication failure"),
    "4776": ("authentication_success", 0.12, "Windows credential validation event"),
    "5140": ("lateral_movement", 0.18, "Windows network share access event"),
    "7045": ("service_installation", 0.22, "Windows service installation event"),
}

STAGE_INFO = {
    "walking": {
        "title": "Movement activity", "type": "user", "weight": 1, "mitre": []
    },
    "authentication_success": {
        "title": "Successful authentication", "type": "user", "weight": 3,
        "mitre": [{"id": "T1078", "name": "Valid Accounts"}]
    },
    "access_declined": {
        "title": "Access declined", "type": "suspicious", "weight": 5, "mitre": []
    },
    "privileged_session": {
        "title": "Privileged session established", "type": "suspicious", "weight": 7,
        "mitre": [{"id": "T1548", "name": "Abuse Elevation Control Mechanism"}]
    },
    "security_group_modification": {
        "title": "Security group modification", "type": "suspicious", "weight": 8,
        "mitre": [{"id": "T1098", "name": "Account Manipulation"}]
    },
    "account_management": {
        "title": "Account management activity", "type": "suspicious", "weight": 7,
        "mitre": [{"id": "T1136", "name": "Create Account"}]
    },
    "credential_use": {
        "title": "Credential use", "type": "suspicious", "weight": 5,
        "mitre": [{"id": "T1078", "name": "Valid Accounts"}]
    },
    "hacking_activity": {
        "title": "Command or process activity", "type": "suspicious", "weight": 6,
        "mitre": [{"id": "T1059", "name": "Command and Scripting Interpreter"}]
    },
    "service_installation": {
        "title": "Service installation activity", "type": "suspicious", "weight": 8,
        "mitre": [{"id": "T1543", "name": "Create or Modify System Process"}]
    },
    "lateral_movement": {
        "title": "Lateral movement", "type": "suspicious", "weight": 8,
        "mitre": [{"id": "T1021", "name": "Remote Services"}]
    },
    "usb_insertion": {
        "title": "Removable media activity", "type": "suspicious", "weight": 5,
        "mitre": [{"id": "T1091", "name": "Replication Through Removable Media"}]
    },
    "exfiltration": {
        "title": "Potential data exfiltration", "type": "malicious", "weight": 10,
        "mitre": [{"id": "T1041", "name": "Exfiltration Over C2 Channel"}]
    },
    "defence_evasion": {
        "title": "Defence evasion activity", "type": "malicious", "weight": 9,
        "mitre": [{"id": "T1070", "name": "Indicator Removal"}]
    },
    "session_exit": {
        "title": "Session termination", "type": "user", "weight": 1, "mitre": []
    },
    "other": {
        "title": "Observed activity", "type": "system", "weight": 1, "mitre": []
    },
}

STAGE_PATTERNS = {
    "authentication_success": [
        r"\bsuccess(?:ful(?:ly)?)?\s+(?:login|logon|authentication)\b",
        r"\b(?:login|logon|authentication)\s+(?:success|succeeded|accepted|granted)\b",
        r"\baccess\s+granted\b",
        r"\bauthenticated\b",
        r"\baccepted\s+(?:password|publickey)\b",
        r"\bsession\s+opened\b",
        r"\bsign[- ]?in\s+succeeded\b",
        r"\bconsolelogin.*success\b",
    ],
    "access_declined": [
        r"\bfailed\s+(?:login|logon|authentication)\b",
        r"\b(?:login|logon|authentication)\s+(?:failed|failure|denied|rejected)\b",
        r"\baccess\s+(?:denied|declined|blocked)\b",
        r"\binvalid\s+(?:password|credential|user)\b",
        r"\bpermission\s+denied\b",
        r"\bunauthori[sz]ed\b",
    ],
    "privileged_session": [
        r"\bsudo\b",
        r"\bsu\s+(?:-|root)\b",
        r"\broot\s+session\b",
        r"\badministrator\s+(?:role|rights|privileges|session)\b",
        r"\bspecial\s+privileges\b",
        r"\belevated\s+(?:session|privilege|rights)\b",
        r"\bassumerole\b.*\badmin",
        r"\bprivilege(?:d)?\s+(?:session|elevation|assignment)\b",
    ],
    "security_group_modification": [
        r"\badded\s+to\s+(?:a\s+)?(?:security|admin|administrator|global|local)\s+group\b",
        r"\bgroup\s+membership\s+(?:changed|modified|updated)\b",
        r"\bmember\s+(?:added|removed)\b.*\bgroup\b",
        r"\bsecurity\s+group\s+(?:changed|modified|updated)\b",
        r"\brole\s+membership\s+(?:changed|updated)\b",
    ],
    "account_management": [
        r"\baccount\s+(?:created|enabled|disabled|deleted|modified)\b",
        r"\buser\s+(?:created|enabled|disabled|deleted)\b",
        r"\bpassword\s+(?:reset|changed)\b",
        r"\bnew\s+(?:user|account)\b",
    ],
    "credential_use": [
        r"\bexplicit\s+credential",
        r"\bcredential(?:s)?\s+(?:used|supplied|validated)\b",
        r"\bpass[- ]?the[- ]?hash\b",
        r"\btoken\s+(?:used|assumed|issued)\b",
    ],
    "hacking_activity": [
        r"\bpowershell\b",
        r"\bcmd(?:\.exe)?\b",
        r"\bbash\b",
        r"\bsh\b.*\b-c\b",
        r"\bcommand\s+execut",
        r"\bprocess\s+(?:created|started|executed)\b",
        r"\bencoded\s+command\b",
        r"\bwhoami\b",
        r"\bnet\s+user\b",
        r"\bcurl\b",
        r"\bwget\b",
        r"\bpython(?:3)?\b.*\b-c\b",
    ],
    "service_installation": [
        r"\bservice\s+(?:installed|created|registered)\b",
        r"\bsystemd\s+(?:unit|service).*(?:created|enabled)\b",
        r"\blaunchd\b.*\b(?:loaded|installed)\b",
        r"\bnew\s+service\b",
    ],
    "lateral_movement": [
        r"\blateral\s+movement\b",
        r"\bremote\s+(?:login|logon|session|connection|execution)\b",
        r"\bnetwork\s+share\b",
        r"\badmin\$\b",
        r"\bsmb\b",
        r"\brdp\b",
        r"\bssh\b.*\b(?:to|from)\b",
        r"\bwinrm\b",
        r"\bpsexec\b",
        r"\bremote\s+desktop\b",
    ],
    "usb_insertion": [
        r"\busb\b",
        r"\bremovable\s+(?:media|drive|storage|volume)\b",
        r"\bmass[- ]storage\b",
        r"\bflash\s+drive\b",
        r"\bthumb\s+drive\b",
        r"\bexternal\s+drive\b",
    ],
    "exfiltration": [
        r"\bexfiltrat",
        r"\bdata\s+(?:export|theft|leak)\b",
        r"\bupload(?:ed|ing)?\b.*\b(?:external|cloud|dropbox|drive|s3|paste)\b",
        r"\bcopy(?:ied|ing)?\b.*\b(?:usb|removable|external)\b",
        r"\boutbound\s+transfer\b",
        r"\bfiles?\s+(?:sent|transferred|uploaded)\b",
    ],
    "defence_evasion": [
        r"\baudit\s+log\s+(?:cleared|deleted)\b",
        r"\blog\s+(?:cleared|deleted|wiped)\b",
        r"\bdisable(?:d|ing)?\s+(?:antivirus|defender|logging|edr)\b",
        r"\bsecurity\s+tool\s+(?:disabled|stopped)\b",
        r"\bdelete(?:d|ing)?\s+(?:history|logs?)\b",
    ],
    "session_exit": [
        r"\blogoff\b",
        r"\blogout\b",
        r"\bsign[- ]?out\b",
        r"\bsession\s+(?:closed|ended|terminated)\b",
        r"\bdisconnected\s+session\b",
    ],
    "walking": [
        r"\bphysical\s+movement\b",
        r"\bmovement\s+between\s+(?:zones|rooms|areas)\b",
        r"\bbadge\s+telemetry\b.*\bmovement\b",
    ],
}

REMOTE_PROTOCOL_HINTS = ("ssh", "rdp", "smb", "winrm", "psexec", "remote desktop", "network share", "admin$")
EXTERNAL_HINTS = ("external", "internet", "cloud", "dropbox", "onedrive", "google drive", "s3", "mega", "pastebin")
SENSITIVE_FILE_HINTS = ("payroll", "board", "finance", "customer", "client", "secret", "confidential", "credential", "password", "pipeline")
