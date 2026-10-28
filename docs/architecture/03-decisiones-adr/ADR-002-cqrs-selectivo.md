# ADR-002: Implementación de CQRS Selectivo (Command Query Responsibility Segregation)

## Estado
Aceptado

## Contexto
El flujo operativo del SOC bancario presenta dos patrones de acceso radicalmente opuestos:
1. **Escritura continua e intensiva**: Registro en milisegundos de veredictos, eventos de auditoría append-only y telemetría de correos entrantes.
2. **Lectura analítica compleja**: Threat hunting difuso con `pg_trgm`, cálculo de falsos positivos/negativos para paneles gerenciales y filtrado multidimensional de incidentes.

## Decisión
Aplicar **CQRS Selectivo**:
- **Comandos (Write)**: Procesados mediante CommandBus, aplicando invariantes de dominio, validación estricta y persistencia en modelos relacionales normalizados.
- **Consultas (Read)**: Despachadas mediante QueryBus hacia vistas materializadas (`mv_dashboard_kpis`, `mv_threat_hunting`) respaldadas por caché de segundo nivel en Redis.

## Consecuencias
- **Positivas**: Las consultas pesadas de tableros nunca bloquean las transacciones críticas de inspección en tiempo real.
- **Negativas**: Necesidad de una estrategia de refresco periódico de vistas materializadas (`REFRESH MATERIALIZED VIEW CONCURRENTLY`).
