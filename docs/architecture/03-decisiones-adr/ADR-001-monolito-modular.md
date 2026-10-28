# ADR-001: Adopción de Monolito Modular sobre Microservicios Distribuidos

## Estado
Aceptado

## Contexto
En el procesamiento en tiempo real de correos corporativos bancarios (MTA inline inspection), la latencia de respuesta debe mantenerse por debajo de 350 ms para no encolar el gateway de transporte de correo. Una arquitectura prematura de microservicios distribuidos introduce saltos de red HTTP/gRPC adicionales, problemas de consistencia eventual y alta complejidad operativa en la orquestación Kubernetes.

## Decisión
Implementar un **Monolito Modular** estructurado mediante Arquitectura Hexagonal. Cada módulo funcional (IAM, Detección, Incidentes, IOCs, Reporting, Dataset) opera con fronteras de dominio estrictas y contratos por puertos e interfaces, permitiendo invocaciones en memoria de alto rendimiento y facilitando una futura extracción a microservicios independientes solo si la escala lo demanda.

## Consecuencias
- **Positivas**: Latencia mínima (in-memory execution), transacciones de base de datos atómicas cuando se requieren, facilidad de despliegue y testing.
- **Negativas**: El escalado horizontal escala todos los módulos juntos (mitigado mediante separación de procesos para workers asíncronos).
