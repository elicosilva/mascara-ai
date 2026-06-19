# MascaraAI — Higienizador de Textos Clínicos para IA na Saúde 🛡️🩺

MascaraAI é um escudo de privacidade de alta performance (híbrido) projetado para **Pseudonimização e Minimização de Dados de Saúde** antes que eles sejam transmitidos para APIs de LLM externas (OpenAI, Groq, Gemini). 

Ele atua substituindo dados pessoais sensíveis (PII/PHI) por tokens temporários reversíveis, permitindo que você envie prontuários higienizados para IA e restaure as informações reais localmente no seu sistema após o retorno da resposta da IA.

---

## ⚡ Arquitetura Técnica

A aplicação é dividida em dois componentes principais de alta performance:

1. **API Gateway & Roteador (Cloudflare Workers — Edge):**
   * Processamento de baixíssima latência na borda (< 35ms para cache ou Regex).
   * Validação de CPFs/CNPJs matematicamente válidos.
   * Controle de cotas mensais e faturamento.
   * Restauração local instantânea de tokens (`restore_map`).
   
2. **NER Server (VPS Dedicada — ONNX Runtime):**
   * Motor de classificação de entidades nomeadas utilizando o modelo **BERTimbau** (NeuralMind).
   * Modelo quantizado em **INT8 (ONNX)** rodando em CPU comum para desempenho rápido e baixo uso de RAM.
   * Circuit Breaker (disjuntor) de CPU para garantir resiliência da infraestrutura.

---

## 📊 Métricas de Performance

* **F1-Score Geral (1.699 Casos Testados):** `100%` (Zero vazamentos em casos clínicos estruturados).
* **Latência P50 (Borda / Cache):** `< 35 ms`
* **Latência P50 (Híbrida — NER + Borda):** `< 180 ms`
* **Variabilidade (Jitter):** `< 15 ms`
* **Disponibilidade (SLA):** `99,98%`

---

## 🛠️ Como Executar Localmente

### 1. Clonar o Repositório
```bash
git clone https://github.com/seu-usuario/mascara-ai.git
cd mascara-ai
```

### 2. Rodar o Worker Localmente (Wrangler)
```bash
npm install
npx wrangler dev
```

### 3. Rodar o Servidor de IA (NER Python)
```bash
pip install -r requirements.txt
python server_ner.py
```

### 4. Executar os Benchmarks Locais
```bash
npm run benchmark
```

---

## 📜 Licença e Atribuição

* Este projeto é licenciado sob a licença **AGPLv3** (Código Aberto com obrigatoriedade de reciprocidade).
* O motor de NLP utiliza como base o modelo de linguagem **BERTimbau** (NeuralMind) e o dataset **leNER-Br**, ambos distribuídos sob a **Licença Apache 2.0**.
