# Guia de Integração MascaraAI no n8n

Este guia descreve como integrar o gateway **MascaraAI** em fluxos do **n8n** para anonimização e conformidade de dados antes de enviar mensagens a modelos de IA (OpenAI, Claude, etc.).

---

## 1. Estrutura do Fluxo Padrão no n8n

Para um fluxo de chat ou processamento de documentos típico, a arquitetura deve seguir esta ordem:

```
[ Gatilho / Webhook ] 
       ↓
[ MascaraAI: /api/scan ]  ──(Salva o `restore_map` e `classification_report` no banco)
       ↓
[ Nó de IA: OpenAI/Claude ] (Recebe apenas o texto mascarado seguro)
       ↓
[ MascaraAI: /api/restore ] (Reidrata o texto da IA com o `restore_map` original)
       ↓
[ Resposta Final: Cliente/WhatsApp ]
```

---

## 2. Configurando a Chamada de Mascaramento (/api/scan)

Adicione um nó **HTTP Request** no n8n com as seguintes configurações:

* **Method**: `POST`
* **URL**: `https://sua-api.mascaraai.com/api/scan`
* **Headers**:
  * `X-API-Key`: `msk_seu_token_aqui`
  * `Content-Type`: `application/json`
* **Body Parameters (JSON)**:
  ```json
  {
    "texto": "={{ $json.body.message }}",
    "categoria": "uti_evolucao"
  }
  ```

### Resposta Retornada pelo MascaraAI:
O nó retornará o JSON contendo os metadados e o texto seguro:
```json
{
  "safe_text": "Paciente ⟦PII:NOME_PESSOA:7C12⟧, CPF ⟦PII:CPF:B9A2⟧...",
  "restore_map": {
    "⟦PII:NOME_PESSOA:7C12⟧": "João da Silva",
    "⟦PII:CPF:B9A2⟧": "123.456.789-00"
  },
  "entities_found": 2,
  "categories": ["NOME_PESSOA", "CPF"],
  "classification_report": {
    "masked_categories": ["NOME_PESSOA", "CPF"],
    "suspected_unmasked_items": [],
    "risk_score": 40,
    "audit_context": {
      "has_pii": true,
      "policy_mode": "balanced",
      "compliance_alert": false
    }
  },
  "processing_ms": 12,
  "ner_ok": true
}
```

---

## 3. Auditando e Monitorando Alertas Programaticamente no n8n

Você pode usar o resultado da `classification_report` para auditoria sem precisar de revisão manual contínua.

### Nó Switch no n8n:
Adicione um nó **Switch** após a chamada de scan para analisar o risco:
* **Value 1**: `{{ $json.classification_report.audit_context.compliance_alert }}`
* **Condition**: `is True`
  * **Ação**: Direciona o fluxo para um nó de notificação (ex: **Slack** ou **Email**) avisando o time de compliance corporativo:
    > *"Atenção: A chave de API do n8n processou uma mensagem contendo alta densidade de PII (Risk Score: {{ $json.classification_report.risk_score }}). Categoria dos dados: {{ $json.classification_report.masked_categories.join(', ') }}"*

---

## 4. Reidratando a Resposta (/api/restore)

Quando a IA (ex: GPT-4) responde ao texto mascarado, ela pode citar os tokens fictícios (ex: *"O paciente ⟦PII:NOME_PESSOA:7C12⟧ deve tomar..."*). 
Para converter os tokens de volta para os dados reais do paciente antes de responder no WhatsApp:

Adicione um nó **HTTP Request** após a resposta do LLM:
* **Method**: `POST`
* **URL**: `https://sua-api.mascaraai.com/api/restore`
* **Headers**:
  * `X-API-Key`: `msk_seu_token_aqui`
  * `Content-Type`: `application/json`
* **Body Parameters (JSON)**:
  ```json
  {
    "text": "={{ $json.openai_response_text }}",
    "restore_map": "={{ $node['HTTP Request Scan'].json.restore_map }}"
  }
  ```

O resultado conterá o campo `restored_text` com o nome original do paciente restaurado perfeitamente!
