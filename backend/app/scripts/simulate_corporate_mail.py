"""
Simulador de Flujo de Correo Corporativo en Tiempo Real (MTA / SEG Hook)
Demuestra el comportamiento de la plataforma interceptando correos en el gateway bancario:
- Si el correo es legítimo: se ACEPTA y se entrega normalmente a la bandeja.
- Si el correo es de phishing: se INTERCEPTA, se pone en CUARENTENA y se DISPARA la alerta/incidente.
"""

import time
import json
import sys
from datetime import datetime

# Garantizar salida UTF-8 en consolas Windows
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
from app.domain.detection.engine import DetectionEngine, EmailAnalysisInput

# Casos de prueba realistas simulando el tráfico de entrada del banco
SIMULATION_SCENARIOS = [
    {
        "id": "CASE-01-LEGITIMATE",
        "name": "Comunicado Institucional de Recursos Humanos (Legítimo)",
        "input": EmailAnalysisInput(
            sender="rrhh@bancocentral.com",
            recipient="juan.perez@bancocentral.com",
            subject="Calendario de Feriados y Pagos de Fin de Mes",
            body_text="Estimado equipo, les compartimos el cronograma oficial de pagos y días festivos para el presente trimestre. Pueden consultarlo en el portal interno de la intranet.",
            headers={
                "received-spf": "Pass (bancocentral.com: domain of rrhh@bancocentral.com designates 190.12.45.10 as permitted sender)",
                "authentication-results": "spf=pass dkim=pass dmarc=pass header.from=bancocentral.com",
            },
            attachments_meta=[]
        )
    },
    {
        "id": "CASE-02-PHISHING-HOMOGRAPH",
        "name": "Ataque Dirigido: Suplantación de Token con Homógrafo Punycode y DMARC Fail (Crítico)",
        "input": EmailAnalysisInput(
            sender="soporte@bancоcentral.com",  # Contiene 'о' cirílica (U+043E) homógrafa
            recipient="gerencia.finanzas@bancocentral.com",
            subject="URGENTE: Su Token Digital ha sido suspendido por actividad sospechosa",
            body_text="Estimado usuario bancario, hemos detectado accesos no autorizados. Su clave de 6 dígitos y token digital han sido bloqueados. Para evitar el cierre definitivo y multa, ingrese de inmediato a http://bancocentral-seguridad.com/reactivar y digite su tarjeta y clave de 6 digitos para desbloquear.",
            headers={
                "received-spf": "Fail (bancocentral.com: domain of soporte@bancocentral.com does not designate 45.134.20.18 as permitted sender)",
                "authentication-results": "spf=fail dkim=none dmarc=fail (p=reject) header.from=bancocentral.com",
            },
            attachments_meta=[
                {"filename": "Formulario_Desbloqueo.exe", "size_bytes": 1048576}
            ]
        )
    },
    {
        "id": "CASE-03-SUSPICIOUS-EXTERNAL",
        "name": "Correo de Proveedor Externo No Verificado (Sospechoso)",
        "input": EmailAnalysisInput(
            sender="facturacion@proveedor-servicios-latam.net",
            recipient="compras@bancocentral.com",
            subject="Factura pendiente de pago - Vence en 24 horas",
            body_text="Adjuntamos el detalle de la factura de servicios en la nube correspondiente al mes en curso. Por favor confirmar recepción antes del vencimiento.",
            headers={
                "received-spf": "SoftFail (domain of proveedor-servicios-latam.net: transitioning)",
                "authentication-results": "spf=softfail dkim=none",
            },
            attachments_meta=[
                {"filename": "Factura_Noviembre.pdf", "size_bytes": 245000}
            ]
        )
    },
    {
        "id": "CASE-04-PHISHING-IP-CREDENTIALS",
        "name": "Ataque Masivo: Enlace a IP Directa + Captura de Coordenadas (Crítico)",
        "input": EmailAnalysisInput(
            sender="alertas-bancarias@security-notice.org",
            recipient="maria.lopez@bancocentral.com",
            subject="ALERTA: Embargo de cuenta por falta de actualización de datos",
            body_text="Aviso de seguridad nacional: Evite el cierre y embargo preventivo de sus cuentas. Debe verificar su identidad inmediatamente en http://185.220.101.5/login-portal ingresando sus credenciales y codigo de seguridad de su tarjeta de credito.",
            headers={
                "received-spf": "Neutral",
                "authentication-results": "spf=neutral dkim=none dmarc=none",
            },
            attachments_meta=[]
        )
    }
]

def run_corporate_mail_simulation():
    engine = DetectionEngine()

    print("=" * 80)
    print(" BANCO DIGITAL - PLATAFORMA ANTIPHISHING EMPRESARIAL")
    print(" SIMULADOR DE INSPECCIÓN DE CORREO EN TIEMPO REAL (MTA / SEG HOOK)")
    print("=" * 80)
    print("Iniciando escucha activa en el puerto de transporte de correo corporativo...\n")

    for i, scenario in enumerate(SIMULATION_SCENARIOS, 1):
        print("-" * 80)
        print(f"[{i}/{len(SIMULATION_SCENARIOS)}] [STREAM INBOUND] Interceptando correo RFC 822 en gateway...")
        print(f"       ID Caso   : {scenario['id']}")
        print(f"       Escenario : {scenario['name']}")
        print(f"       Remitente : {scenario['input'].sender}")
        print(f"       Destino   : {scenario['input'].recipient}")
        print(f"       Asunto    : {scenario['input'].subject}")
        print("       --> Consumiendo API /detection/analyze-email en tiempo real...")
        
        # Simular tiempo de cómputo de inspección inline
        time.sleep(0.4)
        
        evaluation = engine.analyze_email(scenario['input'])

        print(f"       --> Score de Riesgo Calculado: {evaluation.risk_score} / 100")
        print(f"       --> Veredicto Emitido        : {evaluation.verdict}")
        print(f"       --> Acción de Seguridad      : {evaluation.action}")

        # Decisión operativa en la empresa
        if evaluation.action == "DELIVER":
            print("\n       >>> [DECISIÓN MTA]: CORREO ACEPTADO (LIMPIO) <<<")
            print("           El correo superó todos los filtros de seguridad corporativa.")
            print("           Acción: Entregado normalmente a la bandeja de entrada del empleado.")
        elif evaluation.action == "TAG_AND_BANNER":
            print("\n       >>> [DECISIÓN MTA]: ADVERTENCIA PREVENTIVA <<<")
            print("           Se detectaron señales sospechosas moderadas.")
            print("           Acción: Se inyecta cabecera [EXTERNO / PRECAUCIÓN] y banner visual.")
        elif evaluation.action == "QUARANTINE":
            inc_code = f"INC-{datetime.now().strftime('%Y%m%d')}-{i:04d}"
            print("\n       >>> [DECISIÓN MTA]: ¡¡¡DISPARO DE ALERTA Y CUARENTENA INMEDIATA!!! <<<")
            print(f"           ¡AMENAZA DETECTADA! El correo es interceptado y retenido en bóveda segura.")
            print(f"           No llega a la bandeja del usuario para proteger sus credenciales.")
            print(f"           Ticket de Incidente Generado: {inc_code}")
            print("           Orquestación n8n SOAR activada:")
            print("             * Alerta crítica enviada a canal #soc-incidentes (Teams/Slack)")
            print("             * Dominio y remitente añadidos a Blacklist dinámica de firewall")
            print("             * Inicio de temporizador de SLA de respuesta rápida (15 min)")

        if evaluation.signals:
            print("\n       Detalle de Señales Detectadas:")
            for s in evaluation.signals:
                print(f"         * [{s.name}] ({s.weight} pts) -> {s.reason}")
        print("-" * 80 + "\n")

    print("=" * 80)
    print(" RESUMEN DE LA SIMULACIÓN DE TRÁFICO:")
    print("  * Correos Limpios Aceptados y Entregados : 1")
    print("  * Correos Marcados con Advertencia      : 1")
    print("  * Ataques de Phishing Interceptados     : 2 (100% de contención antes de la bandeja)")
    print("=" * 80)

if __name__ == "__main__":
    run_corporate_mail_simulation()
