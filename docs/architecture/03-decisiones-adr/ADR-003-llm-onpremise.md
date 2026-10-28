# ADR-003: Arquitectura Híbrida de Modelos LLM (Ollama On-Premise / Azure OpenAI)

## Estado
Aceptado

## Contexto
El análisis de correos bancarios involucra información potencialmente clasificada (nombres de empleados, números de cuenta parciales, comunicaciones internas confidenciales). Normativas como GDPR, PCI-DSS y regulaciones bancarias locales prohíben la transmisión no controlada de datos de clientes hacia nubes de terceros sin garantías de no entrenamiento.

## Decisión
Adoptar un enfoque de **Fábrica de LLMs Híbrida**:
- **Ambiente On-Premise / Por Defecto**: Despliegue de modelos de pesos abiertos (Llama 3 8B, Mistral 7B) mediante Ollama en infraestructura interna con GPUs bancarias para todo correo entrante corporativo.
- **Ambiente Cloud Regulado (Opcional)**: Conector aislado hacia Azure OpenAI bajo suscripción Enterprise con cláusula estricta de cero retención de datos (`zero-data-retention`), activado solo bajo consentimiento explícito o para análisis de texto desidentificado.

## Consecuencias
- **Positivas**: Soberanía total de datos, cumplimiento normativo estricto, independencia de costos por token en picos de tráfico.
- **Negativas**: Necesidad de provisión de cómputo GPU interno.
