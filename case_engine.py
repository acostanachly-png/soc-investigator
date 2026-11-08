"""Casos de investigación SOC con correlación reproducible (no confirma intrusiones).

Una regla necesita señales complementarias y conserva todas las filas del Excel.
Las reglas no dependen de IP, usuario o nombre de archivo específicos del curso.
"""
from __future__ import annotations

from collections import Counter
from datetime import timedelta
import re
from typing import Any

import pandas as pd

from engine import _auth_kind


def _str(v: Any) -> str:
    return '' if pd.isna(v) else str(v)


def _rows(frame: pd.DataFrame, max_count: int = 80) -> list[dict]:
    fields = ("log_id", "timestamp", "host", "event_id", "user", "src_ip",
              "dest_host", "log_source", "event", "command", "status", "severity")
    result = []
    for _, r in frame.sort_values('dt', kind='stable').head(max_count).iterrows():
        item = {k: _str(r.get(k, '')) for k in fields}
        item['excel_row'] = int(r['excel_row'])
        result.append(item)
    return result


def _case(kind: str, label: str, severity: str, justification: str,
          events: pd.DataFrame, recommendation: str, score: str,
          details: dict | None = None) -> dict:
    evidence = _rows(events)
    return {
        'id': '', 'categoria': kind, 'titulo': label, 'criticidad': severity,
        'estado': 'Hipótesis de incidente, pendiente de validación',
        'confianza': score, 'justificacion': justification,
        'evidencias': evidence,
        'filas': [int(v) for v in events.sort_values('dt', kind='stable')['excel_row'].tolist()],
        'recomendacion': recommendation,
        'detalle': details or {},
    }


def detect_cases(logs: pd.DataFrame) -> list[dict]:
    """Devuelve investigaciones con 2+ señales independientes.

    No afirma causalidad, ejecución exitosa de payload, exfiltración real ni abuso confirmado.
    """
    if logs.empty or 'dt' not in logs or logs['dt'].notna().sum() == 0:
        return []
    df = logs.copy()
    for col in ('user','src_ip','host','event_id','event','command','status','dest_host'):
        if col not in df:
            df[col] = ''
        df[col] = df[col].fillna('').astype(str)
    df = df[df['dt'].notna()].sort_values('dt', kind='stable')
    df['kind'] = df.apply(_auth_kind, axis=1)
    idcol = df['event_id'].str.strip().str.upper()
    cmdcol = df['command'].str.lower()
    eventcol = df['event'].str.lower()
    cases = []

    # 1) Rociado: IP que falla contra múltiples identidades en <=20 min.
    failure = df[df['kind'] == 'failure']
    success = df[df['kind'] == 'success']
    for ip, attempts in failure[failure['src_ip'].ne('')].groupby('src_ip'):
        attempts = attempts.sort_values('dt')
        best = None
        for _, first in attempts.iterrows():
            group = attempts[(attempts['dt'] >= first['dt']) & (attempts['dt'] <= first['dt'] + pd.Timedelta(minutes=20))]
            if len(group) >= 12 and group['user'].nunique() >= 4 and (best is None or len(group) > len(best)):
                best = group
        if best is None:
            continue
        related_success = success[(success['src_ip'] == ip) & (success['dt'] >= best['dt'].min()) & (success['dt'] <= best['dt'].max() + pd.Timedelta(minutes=20))]
        event_set = pd.concat([best, related_success]).drop_duplicates(subset=['excel_row'])
        privileged = df[(idcol == '4672') & (df['src_ip'] == ip) & (df['dt'] >= best['dt'].min()) & (df['dt'] <= best['dt'].max() + pd.Timedelta(minutes=25))]
        event_set = pd.concat([event_set, privileged]).drop_duplicates(subset=['excel_row'])
        success_msg = f"; {len(related_success)} acceso(s) exitoso(s) posteriores desde esa IP" if len(related_success) else "; sin éxito vinculado en esta ventana"
        cases.append(_case(
            'Fuerza bruta', 'Rociado de contraseñas contra múltiples cuentas',
            'Alto',
            f"La IP de origen {ip} produjo {len(best)} eventos de autenticación fallida contra {best['user'].nunique()} usuarios en 20 minutos{success_msg}. Un evento 4672, de existir, señala privilegios especiales en un inicio, no una elevación de permisos demostrada.",
            event_set,
            'Comprobar autenticación y MFA por usuario; validar la IP con infraestructura y los inicios exitosos, bloquear solo tras la verificación operativa.',
            'Alta para el patrón de intentos; identidad del actor y autorización desconocidas',
            {'ip':ip, 'fallos':int(len(best)), 'cuentas':int(best['user'].nunique()),'exitos':int(len(related_success))}
        ))

    # 2) RDP: fallos seguidos de éxito, privilegios y ejecución; relacionar etapas por usuario y tiempo.
    for (user, ip), attempts in failure[(failure['user'].ne('')) & (failure['src_ip'].ne(''))].groupby(['user','src_ip']):
        if len(attempts) < 3:
            continue
        same_succ = success[(success['user'] == user) & (success['src_ip'] == ip)]
        for _, s in same_succ.iterrows():
            prior = attempts[(attempts['dt'] <= s['dt']) & (attempts['dt'] >= s['dt'] - pd.Timedelta(minutes=30))]
            if len(prior) < 3:
                continue
            later = df[(df['user'] == user) & (df['dt'] >= s['dt']) & (df['dt'] <= s['dt'] + pd.Timedelta(minutes=30))]
            specials = later[later['event_id'].str.strip() == '4672']
            commands = later[(later['event_id'].str.strip() == '4688') & later['command'].str.contains(r'(?:powershell|net\.exe|tar\.exe)', flags=re.I, regex=True)]
            if specials.empty or commands.empty:
                continue
            associated = pd.concat([prior, later]).drop_duplicates(subset=['excel_row'])
            rdp = 'logontype=10' in (s['event'] + ' '.join(prior['event'].tolist())).lower()
            shares = later[later['event_id'].str.strip().isin(['5140','5145'])]
            outbound = later[(later['event_id'].str.strip() == '5156') & later['dest_host'].str.contains(':443',regex=False)]
            details = {'usuario':user, 'ip_inicial':ip,'fallos':int(len(prior)),
                       'rdp':bool(rdp),'accesos_recurso':int(len(shares)), 'conexiones_salientes':int(len(outbound))}
            cases.append(_case(
                'Movimiento lateral', 'Secuencia administrativa: inicio remoto, procesos y recurso compartido',
                'Crítico' if len(shares) and len(outbound) else 'Alto',
                f"La cuenta {user} desde {ip} presenta {len(prior)} fallos y posterior éxito{' RDP' if rdp else ''}; después hay un evento 4672 y ejecución de herramientas. En la ventana hay {len(shares)} evento(s) de acceso a recurso compartido y {len(outbound)} conexión(es) saliente(s) permitida(s). La coincidencia por usuario/tiempo sugiere investigar desplazamiento entre equipos; no prueba que todos los registros sean una misma sesión ni que se transfiriera contenido.",
                associated,
                'Validar la autenticidad del acceso remoto y tickets; revisar identificadores de sesión, auditorías de archivos, EDR y proxy; preservar evidencia antes de contener.',
                'Alta en la secuencia temporal; baja para atribución causal sin identificador de sesión',details
            ))
            break

    # 3) Uso anómalo de cuenta + lectura masiva + eliminación de sombras.
    encoded = df[(idcol == '4688') & cmdcol.str.contains(r'powershell[^\n]{0,100}(?:-enc\b|-encodedcommand\b)', regex=True)]
    for _, first in encoded.iterrows():
        near = df[(df['user'] == first['user']) & (df['src_ip'] == first['src_ip']) &
                  (df['dt'] >= first['dt']) & (df['dt'] <= first['dt'] + pd.Timedelta(minutes=20))]
        file_ops = near[(near['event_id'].str.strip() == '4663') & near['command'].str.contains('File access:',regex=False)]
        shadows = near[near['command'].str.contains(r'vssadmin(?:\.exe)?\s+delete\s+shadows',flags=re.I, regex=True)]
        if len(file_ops) < 8 or shadows.empty:
            continue
        evidence = pd.concat([pd.DataFrame([first]), file_ops, shadows]).drop_duplicates(subset=['excel_row'])
        cases.append(_case('Comandos y procesos', 'Cuenta con lectura masiva y modificación potencial de recuperación',
            'Alto', f"El usuario {first['user']} desde {first['src_ip']} registró PowerShell con parámetro de comando codificado, {len(file_ops)} accesos a archivos identificados y un comando 'vssadmin delete shadows' en una ventana de 20 minutos. La evidencia indica invocación del comando; no confirma que las copias se hayan borrado.",
            evidence,
            'Verificar autorización de la cuenta de servicio, contenido del script, resultados del comando, estado de respaldos y accesos a archivos.',
            'Alta para la sucesión de eventos; resultado de eliminación sin verificar',
            {'usuario':first['user'], 'archivos':int(len(file_ops)), 'comando_sombras':True}))
        
    # 4) Preparación de archivos + tráfico HTTPS saliente medido.
    archivers = df[(idcol == '4688') & cmdcol.str.contains(r'(?:7z(?:\.exe)?\s+a\b|tar(?:\.exe)?\s+.*\s-f\b)', flags=re.I, regex=True)]
    for _, first in archivers.iterrows():
        near = df[(df['user'] == first['user']) & (df['src_ip'] == first['src_ip']) & (df['host'] == first['host']) &
                  (df['dt'] > first['dt']) & (df['dt'] <= first['dt'] + pd.Timedelta(minutes=30))]
        proxy = near[(near['event_id'].str.upper() == 'PROXY_ACCESS') & near['event'].str.contains('POST',case=False) &
                     near['command'].str.contains('bytes_out=',case=False)]
        if len(proxy) < 4:
            continue
        total = 0
        for _, p in proxy.iterrows():
            match = re.search(r'bytes_out\s*=\s*(\d+)',p['command'])
            if match:
                total += int(match.group(1))
        evidence = pd.concat([pd.DataFrame([first]), proxy]).drop_duplicates(subset=['excel_row'])
        cases.append(_case('Otras anomalías', 'Posible salida de datos: archivo comprimido y solicitudes HTTPS',
            'Crítico', f"Tras ejecutarse una orden de compresión con {first['user']} en {first['host']}, se registraron {len(proxy)} solicitudes HTTPS POST del mismo usuario, IP y equipo con aproximadamente {total/1_000_000:.2f} MB contabilizados en el campo bytes_out. Es evidencia de volumen saliente informado por proxy, no de que el archivo comprimido fuese el contenido transmitido ni de exfiltración confirmada.",
            evidence,
            'Inspeccionar destino, proxy, contenido y autorización de transferencias; preservar la bitácora de DLP y determinar qué datos salieron.',
            'Alta para tráfico y compresión; contenido transferido no demostrado',
            {'usuario':first['user'], 'transferencias':int(len(proxy)), 'bytes_out':int(total), 'mb_decimales':round(total/1_000_000,2)}))

    # 5) Tarea programada + servicio + ejecuciones relacionadas.
    tasks = df[idcol == '4698']
    for _, task in tasks.iterrows():
        near = df[(df['user'] == task['user']) & (df['host'] == task['host']) &
                  (df['dt'] >= task['dt']) & (df['dt'] <= task['dt'] + pd.Timedelta(minutes=40))]
        services = near[near['event_id'].str.strip() == '7045']
        if services.empty:
            continue
        # ID 4688 con ejecutables fuera de directorios estándar en ProgramData.
        repeated = near[(near['event_id'].str.strip() == '4688') & near['command'].str.contains(r'\\ProgramData\\',case=False, regex=True)]
        if len(repeated) < 2:
            continue
        evidence = pd.concat([pd.DataFrame([task]), services, repeated]).drop_duplicates(subset=['excel_row'])
        cases.append(_case('Otras anomalías', 'Tarea programada, servicio instalado y proceso recurrente',
            'Alto', f"En {task['host']} el usuario {task['user']} generó una tarea programada (4698), una instalación de servicio (7045) y {len(repeated)} arranques de procesos desde ProgramData (4688) en 40 minutos. Compatible con persistencia, pero también con instalaciones legítimas; requiere autorización y firma.",
            evidence,
            'Comparar con cambios aprobados y software inventariado; revisar nombre, ruta, firma digital, hashes y árbol de procesos.',
            'Alta para creación y ejecuciones; propósito malicioso sin verificar',
            {'usuario':task['user'],'equipo':task['host'],'ejecuciones':int(len(repeated))}))

    # 6) Tráfico de exploración web + proceso del servidor que ejecuta comandos.
    requests = df[idcol == 'HTTP_ACCESS']
    for (ip, host), group in requests.groupby(['src_ip','host']):
        group = group.sort_values('dt')
        if len(group) < 10:
            continue
        begin, end = group['dt'].min(), group['dt'].max()
        if (end-begin) > pd.Timedelta(minutes=15):
            continue
        process = df[(df['src_ip'] == ip) & (df['host'] == host) &
                     (df['dt'] >= begin) & (df['dt'] <= end + pd.Timedelta(minutes=10)) &
                     (df['event_id'].str.strip() == '4688') &
                     df['command'].str.contains(r'cmd(?:\.exe)?\s+/c\s+whoami',flags=re.I,regex=True)]
        if process.empty:
            continue
        evidence = pd.concat([group, process]).drop_duplicates(subset=['excel_row'])
        statuses = Counter(group['status'])
        cases.append(_case('Otras anomalías', 'Solicitudes web sensibles y ejecución posterior de un comando',
            'Crítico',f"La IP {ip} solicitó {len(group)} rutas en {host} en 15 minutos (códigos HTTP: {dict(statuses)}). Después se registró 'cmd.exe /c whoami' en ese equipo bajo una identidad de servicio web. La correlación temporal/host es compatible con ejecución remota, pero no demuestra por sí sola que la solicitud HTTP causara el proceso.",
            evidence,
            'Examinar logs completos de IIS/WAF y procesos con PID/PPID; verificar permisos de carga y archivos web, y activar respuesta a incidentes si se confirma la conexión.',
            'Alta para la coincidencia temporal; explotación causal no demostrada',
            {'ip':ip, 'solicitudes':int(len(group)), 'http_status':dict(statuses)}))

    # Evitar duplicados si otro patrón produce exactamente las mismas filas.
    unique = {}
    for c in cases:
        key=(c['titulo'], tuple(c['filas']))
        unique.setdefault(key,c)
    cases = sorted(unique.values(), key=lambda c: min(c['filas']) if c['filas'] else 999999)
    for i,c in enumerate(cases,1):
        c['id'] = f'INC-{i:02}'
    return cases
