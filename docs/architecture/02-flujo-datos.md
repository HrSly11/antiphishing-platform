# Flujo de Datos y Pipeline de Inspección en Tiempo Real

## 1. Inspección de Correo en el Perímetro Bancario (Inline Mail Inspection)

En una infraestructura empresarial regulada, la plataforma no espera a que un analista consulte URLs de forma manual. El sistema opera como un **servicio webhook / milter en tiempo real** consumido directamente por el Secure Email Gateway (MTA).

```mermaid
sequenceDiagram
    autonumber
    participant MTA as Mail Gateway (Postfix / O365)
    participant API as FastAPI (/analyze-email)
    participant Engine as Detection Engine
    participant Cache as Redis Cache
    participant DB as PostgreSQL
    participant N8N as n8n SOAR
    participant Inbox as Casilla del Empleado

    MTA->>API: POST /api/v1/detection/analyze-email
    API->>Engine: Procesar cabeceras, enlaces y cuerpo
    Engine->>Cache: Verificar Whitelist y Blacklist
    Engine->>Engine: Evaluar Homógrafos, Entropía y DMARC
    
    alt Score < 30 (Limpio)
        Engine-->>API: Veredicto: CLEAN | Acción: DELIVER
        API-->>MTA: 200 OK (Entregar)
        MTA->>Inbox: Depósito normal en bandeja
    else 30 <= Score < 70 (Sospechoso)
        Engine-->>API: Veredicto: SUSPICIOUS | Acción: TAG_AND_BANNER
        API-->>MTA: 200 OK (Inyectar advertencia)
        MTA->>Inbox: Entrega con banner visual de precaución
    else Score >= 70 (Malicioso / Phishing)
        Engine-->>API: Veredicto: MALICIOUS | Acción: QUARANTINE
        API->>DB: Registrar Incidente de Seguridad
        API->>N8N: Disparar Webhook SOAR (Alerta Crítica)
        API-->>MTA: 200 OK (CUARENTENA)
        Note over MTA,Inbox: El correo es RETENIDO en bóveda segura. NO llega al usuario.
        N8N->>N8N: Notificar al canal SOC y bloquear IOC en firewall
    end
```

## 2. Bandas de Decisión Operativa
1. **Pase Limpio (Score 0-29)**: El correo superó las pruebas de reputación y alineación criptográfica SPF/DKIM/DMARC. No se genera fricción para el usuario.
2. **Advertencia Preventiva (Score 30-69)**: Remitente externo desconocido o indicadores sutiles de persuasión. El correo se entrega con cabecera `X-Phish-Warning` y un recuadro superior alertando no ingresar credenciales.
3. **Cuarentena Inmediata (Score 70-100)**: Suplantación de identidad confirmada (homógrafo, combosquatting, phishing de token bancario, adjunto malicioso). Se retiene el correo, se crea un ticket SOC con SLA crítico y se orquesta la contención vía n8n.
