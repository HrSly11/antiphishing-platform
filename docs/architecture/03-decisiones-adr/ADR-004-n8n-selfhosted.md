# ADR-004: Adopción de n8n Self-Hosted para Orquestación SOAR

## Estado
Aceptado

## Contexto
Los flujos de remediación (apertura de tickets en ServiceNow, escalamiento de alertas, integración con firewalls perimetrales, notificaciones por Slack/Teams y envío de reportes) requieren flexibilidad y rápida adaptación por parte del equipo SOC sin obligar a recompilar y desplegar el backend principal.

## Decisión
Desplegar una instancia **autoalojada (self-hosted) de n8n** en el clúster interno de Kubernetes / Docker Compose:
- El backend de FastAPI despacha webhooks firmados con **HMAC SHA-256** hacia n8n.
- n8n asume la responsabilidad de SOAR (Security Orchestration, Automation, and Response) ejecutando la lógica de escalamiento, integración con mensajería y sincronización periódica de datasets.

## Consecuencias
- **Positivas**: Modificación ágil de flujos por el equipo de seguridad sin tocar código fuente, observabilidad visual de ejecuciones, aislamiento ante caídas de APIs externas.
- **Negativas**: Necesidad de mantener una instancia de base de datos o almacenamiento dedicado para n8n.
