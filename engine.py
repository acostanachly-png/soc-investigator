"""Motor auditable de análisis de logs exportados desde un SIEM.
No confirma compromiso: devuelve INDICIOS basados exclusivamente en registros.
"""
from __future__ import annotations

from collections import deque
import re
import unicodedata
from typing import Any

import pandas as pd


FIELDS = {
    "log_id": "Identificador del log",
    "log_source": "Fuente del log",
    "severity": "Severidad de origen (no puntaje SOC)",
    "timestamp": "Fecha y hora",
    "user": "Usuario",
    "src_ip": "IP de origen",
    "host": "Equipo / host",
    "dest_host": "Equipo destino",
    "event": "Evento / descripción",
    "status": "Resultado / estado",
    "event_id": "ID de evento",
    "command": "Comando / proceso",
    "country": "País / ubicación",
}

ALIASES = {
    "log_id": ["log_id", "record_id", "logid", "event_record_id", "registro_id"],
    "log_source": ["log_source", "logsource", "fuente", "source_type"],
    "severity": ["severity", "nivel", "criticidad_origen", "level"],
    "timestamp": ["timestamp", "datetime", "event_time", "timegenerated", "date", "fecha", "hora", "fecha_hora", "time", "eventdatetime", "created_at"],
    "user": ["user", "username", "account", "usuario", "user_name", "account_name", "targetusername", "userprincipalname"],
    "src_ip": ["srcip", "src_ip", "sourceip", "source_ip", "ipaddress", "ip", "ip_origen", "clientip", "calleripaddress", "remoteip"],
    "host": ["host", "computer", "computername", "hostname", "device", "equipo", "workstation", "workstationname"],
    "dest_host": ["destination", "desthost", "destinationhost", "destination_ip", "destip", "targethost", "destinationcomputer", "destino"],
    "event": ["event", "eventname", "event_description", "description", "action", "activity", "message", "detalle", "evento", "operationname", "eventtype"],
    "status": ["status", "result", "outcome", "resultado", "estado", "eventresult", "success", "failure"],
    "event_id": ["eventid", "event_id", "id_evento", "eventcode", "eventcodeid"],
    "command": ["command", "commandline", "process", "processname", "process_command_line", "proceso", "comando", "script"],
    "country": ["country", "location", "pais", "pais_origen", "countryname", "geo", "region"],
}

RECOMMENDATIONS = {
    "Fuerza bruta": "Verificar el usuario y la IP, revisar MFA, bloqueos y registros posteriores sin asumir acceso exitoso.",
    "Inicios sospechosos": "Validar la sesión con el titular, revisar MFA, dispositivo e IP, y confirmar si hubo actividad posterior.",
    "Escalamiento": "Revisar la autorización del cambio y la pertenencia a grupos privilegiados; contrastar con tickets de cambio.",
    "Comandos y procesos": "Revisar el árbol del proceso, firma, usuario ejecutor y el contexto administrativo antes de contener.",
    "Movimiento lateral": "Correlacionar conexiones origen/destino, tipo de acceso, identidad y actividad en los equipos relacionados.",
    "Otras anomalías": "Ampliar la ventana temporal y validar los patrones con inventario, turnos y actividad legítima.",
}


def _key(text: Any) -> str:
    raw = unicodedata.normalize("NFKD", str(text).lower())
    return re.sub(r"[^a-z0-9]+", "", "".join(c for c in raw if not unicodedata.combining(c)))


def suggest_mapping(columns: list[str]) -> dict[str, str | None]:
    options = {name: _key(name) for name in columns}
    used = set()
    result = {}
    for field in FIELDS:
        aliases = [_key(a) for a in ALIASES[field]]
        found = next((name for name, norm in options.items() if norm in aliases and name not in used), None)
        if found is None:
            found = next((name for name, norm in options.items() if any(len(a) > 4 and a in norm for a in aliases) and name not in used), None)
        result[field] = found
        if found:
            used.add(found)
    return result


def _s(value: Any) -> str:
    if pd.isna(value):
        return ""
    return str(value).strip()


def normalize_logs(raw: pd.DataFrame, mapping: dict[str, str | None]) -> pd.DataFrame:
    """Preserva fila de Excel para trazabilidad; no cambia el archivo original."""
    df = pd.DataFrame(index=raw.index)
    for field in FIELDS:
        col = mapping.get(field)
        df[field] = raw[col].map(_s) if col and col in raw.columns else ""
    df["excel_row"] = range(2, len(df) + 2)
    if mapping.get("timestamp"):
        # Interpretación naive: no se inventa zona horaria.
        try:
            df["dt"] = pd.to_datetime(raw[mapping["timestamp"]], errors="coerce", format="mixed")
        except (TypeError, ValueError):
            df["dt"] = pd.to_datetime(raw[mapping["timestamp"]], errors="coerce")
    else:
        df["dt"] = pd.NaT
    return df


def _auth_kind(row: pd.Series) -> str:
    """Distingue autenticación de eventos exitosos *no* relacionados con sesiones.

    Por ejemplo, 4672/4663/5140 son actividades de privilegios o archivos, no
    evidencia de logon solo porque su Result sea Success.
    """
    event_id = str(row.get("event_id", "")).strip().upper()
    status = str(row.get("status", "")).strip().lower()
    text = str(row.get("event", "")).lower()
    if event_id in {"4625", "4771"}:
        return "failure"
    if event_id in {"4624", "528"}:
        return "success"
    if event_id == "4776":
        return "failure" if status in {"failure", "failed", "denied"} else "success" if status in {"success", "successful"} else "other"
    if event_id.isdigit() or event_id in {"HTTP_ACCESS", "PROXY_ACCESS"}:
        return "other"
    if not re.search(r"(?:logon|login|sign[- .]?in|autenticaci[oó]n|inicio de sesi[oó]n)", text, re.I):
        return "other"
    if re.search(r"(?:failed|failure|unsuccessful|incorrect|denied|bad password|fallid|rechaz)", text):
        return "failure"
    if re.search(r"(?:success|successful|exitos|correct|succeeded)", text):
        return "success"
    if status in {"failed", "failure", "denied", "fallido"}:
        return "failure"
    if status in {"success", "successful", "exitoso"}:
        return "success"
    return "other"


def _record(df: pd.DataFrame, idxs: list[int]) -> list[dict[str, str]]:
    records = []
    for _, row in df.loc[idxs[:25]].iterrows():
        records.append({
            "fila": str(row["excel_row"]),
            "log_id": _s(row.get("log_id", "")),
            "fecha": _s(row["timestamp"]),
            "usuario": _s(row["user"]),
            "ip": _s(row["src_ip"]),
            "equipo": _s(row["host"]),
            "destino": _s(row["dest_host"]),
            "evento": _s(row["event"])[:220],
            "id_evento": _s(row["event_id"]),
            "comando": _s(row["command"])[:220],
        })
    return records


def _finding(df: pd.DataFrame, category: str, severity: str, title: str, explanation: str, indices: list[int]) -> dict[str, Any]:
    unique = list(dict.fromkeys(indices))
    return {
        "id": "", "categoria": category, "criticidad": severity,
        "titulo": title, "justificacion": explanation,
        "filas": [int(df.loc[i, "excel_row"]) for i in unique],
        "evidencias": _record(df, unique),
        "recomendacion": RECOMMENDATIONS[category],
    }


def _is_ipv4(value: str) -> bool:
    import ipaddress
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


def analyze(df: pd.DataFrame, brute_threshold: int = 5, window_minutes: int = 10, late_hour_start: int = 0, late_hour_end: int = 5) -> tuple[list[dict[str, Any]], list[str]]:
    """Reglas explícitas, correlacionadas cuando hay timestamp y claves relevantes."""
    findings: list[dict[str, Any]] = []
    limitations: list[str] = []
    if df.empty:
        return [], ["El archivo no contiene filas de datos."]

    logs = df.copy()
    logs["auth_kind"] = logs.apply(_auth_kind, axis=1)
    valid_time = logs["dt"].notna().any()
    if not valid_time:
        limitations.append("No hay fechas/hora interpretables: correlación temporal y horario inhabilitados.")
    if not (logs["user"].ne("").any() or logs["src_ip"].ne("").any()):
        limitations.append("No hay usuario ni IP de origen: no es posible agrupar intentos por identidad.")
    if not logs["event"].ne("").any() and not logs["event_id"].ne("").any():
        limitations.append("Sin campo de evento o ID de evento: muchas reglas no podrán detectar actividad.")
    if logs["command"].eq("").all():
        limitations.append("Sin columna de comandos/procesos: los indicadores de ejecución quedan limitados al texto del evento.")
    if logs["dest_host"].eq("").all():
        limitations.append("Sin equipo destino: no es posible corroborar trayectorias entre equipos.")
    limitations.append("Las detecciones son indicios, no confirmación de intrusión. La ausencia de hallazgos no demuestra seguridad.")
    limitations.append("Las horas se interpretan como aparecen en el Excel; no se conoce su zona horaria ni los turnos autorizados.")
    limitations.append("El evento Windows 4672 registra privilegios especiales en un inicio; por sí solo no demuestra escalamiento.")
    import ipaddress
    doc_ranges = [ipaddress.ip_network(c) for c in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
    if any(any(ipaddress.ip_address(ip) in net for net in doc_ranges) for ip in logs["src_ip"].dropna().unique() if ip and _is_ipv4(ip)):
        limitations.append("El archivo contiene IP de TEST-NET (RFC 5737), reservadas para documentación. Tratar estos destinos como ejemplos del escenario; no como indicadores públicos activos.")

    if valid_time:
        auth = logs[logs["auth_kind"].isin(["failure", "success"]) & logs["dt"].notna()].sort_values("dt")
        # Ataques repetidos de inicio de sesión, por cuenta+IP si están disponibles.
        fail = auth[auth["auth_kind"] == "failure"].copy()
        fail["identity"] = fail.apply(lambda r: (r["user"], r["src_ip"]), axis=1)
        for identity, group in fail.groupby("identity", sort=False):
            if not any(identity):
                continue
            recent: deque[tuple[pd.Timestamp, int]] = deque()
            last_emitted = None
            for idx, r in group.iterrows():
                when = r["dt"]
                while recent and (when - recent[0][0]).total_seconds() > window_minutes * 60:
                    recent.popleft()
                recent.append((when, idx))
                if len(recent) >= brute_threshold and (last_emitted is None or (when - last_emitted).total_seconds() > window_minutes * 60):
                    rows = [i for _, i in recent]
                    findings.append(_finding(logs, "Fuerza bruta", "Alto", "Múltiples accesos fallidos", f"{len(rows)} intentos fallidos dentro de {window_minutes} minutos para usuario '{identity[0] or 'sin dato'}' e IP '{identity[1] or 'sin dato'}'. No prueba acceso exitoso.", rows))
                    last_emitted = when

        # Correlación de autenticación fallida seguida de éxito con misma identidad.
        success = auth[auth["auth_kind"] == "success"]
        for idx, r in success.iterrows():
            identity_match = ((auth["user"] == r["user"]) if r["user"] else pd.Series(True, index=auth.index)) & ((auth["src_ip"] == r["src_ip"]) if r["src_ip"] else pd.Series(True, index=auth.index))
            if not (r["user"] or r["src_ip"]):
                continue
            attempts = auth[identity_match & (auth["auth_kind"] == "failure") & (auth["dt"] <= r["dt"]) & (auth["dt"] >= r["dt"] - pd.Timedelta(minutes=30))]
            if len(attempts) >= 3:
                ids = attempts.index.to_list()[-12:] + [idx]
                findings.append(_finding(logs, "Inicios sospechosos", "Alto", "Acceso exitoso después de fallos", f"Acceso con estado exitoso precedido por {len(attempts)} fallos en 30 minutos para usuario/IP coincidentes. Requiere validar la identidad y los permisos.", ids))

        if 0 <= late_hour_start <= late_hour_end <= 23:
            nights = success[success["dt"].dt.hour.between(late_hour_start, late_hour_end)]
            if not nights.empty:
                findings.append(_finding(logs, "Inicios sospechosos", "Medio", "Accesos en horario de revisión", f"{len(nights)} inicio(s) exitoso(s) entre {late_hour_start:02d}:00 y {late_hour_end:02d}:59 según el reloj del archivo; no constituye anomalía confirmada sin turnos y zona horaria.", nights.index.to_list()[:20]))

        # No inferimos IP anómalas por movilidad/NAT con datos sin inventario ni línea base.
        # Esta comprobación se deja para un enriquecimiento posterior con turnos y MFA.

    # Eventos compatibles con cambios de privilegios.
    elev = re.compile(r"\b(4672|4728|4732)\b|privileg.{0,25}(assign|grant|add|enable|asign|otorg|elev)|added to (administrators|admin group)|agregad.{0,18}administrador|role.{0,20}(grant|assign)|elevaci[oó]n de privilegios|sudo(?:\s|:)", re.I)
    elev_idx = [i for i, r in logs.iterrows() if elev.search(" ".join([r["event"], r["event_id"], r["command"]]))]
    if elev_idx:
        findings.append(_finding(logs, "Escalamiento", "Medio", "Sesiones con privilegios especiales (revisar)", f"{len(elev_idx)} registro(s) se relacionan con privilegios. El ID 4672 no es evidencia suficiente de que se modificaron permisos o se escaló privilegio.", elev_idx[:20]))

    patterns = [
        (r"powershell(?:\.exe)?\s+.{0,45}(?:-enc(?:odedcommand)?\b|-e\s+[A-Za-z0-9+/]{15,})", "PowerShell con contenido codificado"),
        (r"\b(?:vssadmin\s+delete\s+shadows|wbadmin\s+delete\s+catalog)\b", "eliminación de copias/respaldos"),
        (r"\bnet\s+user\b.{0,100}\s/add\b", "creación de cuenta por comando"),
        (r"\b(?:curl|wget)\b.{0,120}\|\s*(?:ba)?sh\b", "descarga y ejecución directa de script"),
        (r"\b(?:mimikatz|procdump)\b", "herramienta de acceso a credenciales o diagnóstico (verificar uso)"),
    ]
    suspicious = []
    descriptions = set()
    for idx, r in logs.iterrows():
        content = " ".join([r["command"], r["event"]])
        for pattern, desc in patterns:
            if re.search(pattern, content, flags=re.I):
                suspicious.append(idx)
                descriptions.add(desc)
                break
    if suspicious:
        findings.append(_finding(logs, "Comandos y procesos", "Alto", "Comandos que requieren investigación", f"{len(suspicious)} registro(s) coinciden con firmas de revisión: {', '.join(sorted(descriptions))}. Se requiere validar el contexto para distinguir administración legítima.", suspicious[:20]))

    # Indicios de conexiones remotas; no catalogar como movimiento lateral confirmado.
    remote_pat = re.compile(r"\b(psexec|winrm|rdp|remote desktop|remote logon|lateral movement|smb session|logon type (3|10)|logontype\s*[=:]\s*(3|10)|ssh connection)\b", re.I)
    remote_idx = [i for i, r in logs.iterrows() if remote_pat.search(" ".join([r["event"], r["command"]]))]
    if remote_idx:
        strength = "Medio" if any(logs.loc[i, "dest_host"] for i in remote_idx) else "Bajo"
        findings.append(_finding(logs, "Movimiento lateral", strength, "Actividad de acceso remoto compatible", f"{len(remote_idx)} registro(s) mencionan protocolos o técnicas de acceso remoto. Sin cadena de equipos y autenticaciones no se puede confirmar movimiento lateral.", remote_idx[:20]))

    # Correlación inter-etapas por la misma cuenta: éxito tras fallos -> privilegios -> comando.
    # Es una hipótesis de riesgo crítico, NUNCA una confirmación de compromiso.
    if valid_time and elev_idx and suspicious:
        success_indices = [i for f in findings if f["categoria"] == "Inicios sospechosos" and f["titulo"] == "Acceso exitoso después de fallos" for i in logs.index[logs["excel_row"].isin(f["filas"])] if logs.loc[i, "auth_kind"] == "success"]
        emitted_users = set()
        for login_idx in success_indices:
            login = logs.loc[login_idx]
            if not login["user"] or login["user"] in emitted_users:
                continue
            follow_elev = [i for i in elev_idx if logs.loc[i, "user"] == login["user"] and pd.notna(logs.loc[i, "dt"]) and login["dt"] <= logs.loc[i, "dt"] <= login["dt"] + pd.Timedelta(minutes=60)]
            for elevation_idx in follow_elev:
                elevation = logs.loc[elevation_idx]
                follow_cmd = [i for i in suspicious if logs.loc[i, "user"] == login["user"] and pd.notna(logs.loc[i, "dt"]) and elevation["dt"] <= logs.loc[i, "dt"] <= login["dt"] + pd.Timedelta(minutes=60)]
                if follow_cmd:
                    findings.append(_finding(logs, "Otras anomalías", "Crítico", "Cadena de eventos correlacionados", "Una misma identidad registra inicio exitoso tras fallos, actividad de privilegios y comando de riesgo en secuencia en <=60 minutos. Es una hipótesis prioritaria: verificar si los eventos comparten la misma sesión y fueron autorizados.", [login_idx, elevation_idx, follow_cmd[0]]))
                    emitted_users.add(login["user"])
                    break

    # Rociado de contraseñas: varias identidades fallidas desde la misma IP.
    if valid_time:
        fails = logs[logs["auth_kind"] == "failure"].dropna(subset=["dt"])
        fails = fails[(fails["src_ip"] != "") & (fails["user"] != "")]
        for src, group in fails.groupby("src_ip"):
            group = group.sort_values("dt")
            for idx, r in group.iterrows():
                current = group[(group["dt"] >= r["dt"]) & (group["dt"] <= r["dt"] + pd.Timedelta(minutes=15))]
                if current["user"].nunique() >= 4:
                    findings.append(_finding(logs, "Otras anomalías", "Alto", "Múltiples cuentas con fallos desde una IP", f"La IP '{src}' registra fallos contra {current['user'].nunique()} identidades en 15 minutos. Patrón compatible con password spraying; necesita validación.", current.index.to_list()[:20]))
                    break

    findings.sort(key=lambda x: {"Crítico": 0, "Alto": 1, "Medio": 2, "Bajo": 3}[x["criticidad"]])
    for n, finding in enumerate(findings, start=1):
        finding["id"] = f"H-{n:03d}"
    return findings, limitations


def summarize(logs: pd.DataFrame, findings: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "registros": len(logs),
        "hallazgos": len(findings),
        "usuarios": int(logs.loc[logs["user"] != "", "user"].nunique()),
        "ip_origen": int(logs.loc[logs["src_ip"] != "", "src_ip"].nunique()),
        "altos": sum(f["criticidad"] in ("Crítico", "Alto") for f in findings),
    }
