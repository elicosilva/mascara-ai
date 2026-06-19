// Policy Layer: Filtra entidades detectadas com base na política (strict/balanced/conservative) e gera o relatório de auditoria
import { gerarToken } from "../utils/helpers.js";

const ARTICLES = new Set(["da", "de", "do", "das", "dos", "e"]);

export class PolicyLayer {
  static async apply(text, regexDetections, nerDetections, strategy, explicitPolicy = {}) {
    // Determina o modo de política ativo (prioridade para a explicitPolicy do request)
    const policyMode = (explicitPolicy.mode || "balanced").toLowerCase().trim();

    // Consolida e deduplica as detecções iniciais
    const rawDetections = [...regexDetections];
    const regexValores = new Set(regexDetections.map(d => d.valor.toLowerCase()));

    // No RAG, para evitar Falsos Positivos de bairros, cidades e nomes corporativos gerais da IA
    // que não devem ser mascarados de forma ampla no contexto de RAG, aceitamos apenas NOME_PESSOA do NER.
    let activeNerDetections = nerDetections;
    if (strategy.name === "RAG_INGEST" || strategy.name === "RAG_QUERY") {
      activeNerDetections = nerDetections.filter(item => item.tipo === "NOME_PESSOA");
    }

    // Agrega as detecções do NER que já não foram cobertas por Regex
    for (const item of activeNerDetections) {
      const valor = String(item.valor || "").trim();
      if (!valor || valor.includes("⟦") || valor.includes("⟧")) continue;
      
      // Se já foi detectado por Regex, só substitui se for NOME_PESSOA (NER tem mais contexto)
      if (regexValores.has(valor.toLowerCase()) && item.tipo !== "NOME_PESSOA") {
        continue;
      }

      if (!text.includes(valor)) continue;

      const token = await gerarToken(item.tipo, valor);
      rawDetections.push({ tipo: item.tipo, token, valor });
      regexValores.add(valor.toLowerCase());
    }

    const filtered = [];
    const finalSet = new Set();

    // Aplica filtros baseados no Policy Mode e Perfil
    for (const item of rawDetections) {
      const valor = item.valor.trim();
      const tipo = item.tipo;
      const dedupeKey = `${tipo}:${valor.toLowerCase()}`;

      if (finalSet.has(dedupeKey)) continue;

      if (strategy.ignoreTypes && strategy.ignoreTypes.includes(tipo)) {
        continue;
      }

      // Se for STRICT, aceita tudo sem filtros
      if (policyMode === "strict" || strategy.name === "STRICT_HEALTH" || strategy.name === "STRICT_GENERIC") {
        filtered.push(item);
        finalSet.add(dedupeKey);
        continue;
      }

      // --- FILTROS BALANCED E CONSERVATIVE ---

      // 1. Filtros para NOME_PESSOA
      if (tipo === "NOME_PESSOA") {
        if (/\d/.test(valor)) continue; // Nomes não contêm números
        if (!/[A-Za-zÀ-Úà-ú]/.test(valor)) continue;

        const tokensNome = valor.replace(/[.,:;()]/g, " ").trim().split(/\s+/).filter(Boolean);
        
        // Balanced/Conservative: Nomes devem ter entre 2 e 6 tokens
        if (tokensNome.length < 2 || tokensNome.length > 6) continue;

        const valido = tokensNome.every(token => {
          const limpo = token.replace(/^(?:dra|dr)\.?/i, "");
          if (!limpo) return true;
          return ARTICLES.has(limpo.toLowerCase()) || /^[A-ZÀÁÉÍÓÚ]/.test(limpo);
        });

        if (!valido) continue;

        // Se for Conservative, rejeita nomes que não comecem estritamente com letra maiúscula em todos os tokens principais
        if (policyMode === "conservative") {
          const namesOnly = tokensNome.filter(t => !ARTICLES.has(t.toLowerCase()));
          const cased = namesOnly.every(t => /^[A-ZÀ-Ú]/.test(t));
          if (!cased) continue;
        }
      }

      // 2. Filtros para PROFISSIONAL_SAUDE
      if (tipo === "PROFISSIONAL_SAUDE") {
        const escapedVal = valor.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        const temTituloNoValor = /\b(?:Dr\.?|Dra\.?|Enf\.?|Enfermeiro|Enfermeira|Fisio\.?|Fisioterapeuta|Psic\.?|Psic[oó]logo|Nutri\.?|Nutricionista|Farm\.?|Farmac[eê]utico)\b/i.test(valor);
        const temTituloNoTexto = new RegExp(`\\b(?:Dr\\.?a?\\.?|Dra\\.?|Enf\\.?|Enfermeiro|Enfermeira|Fisio\\.?|Fisioterapeuta|Psic\\.?|Psic[oó]logo|Nutri\\.?|Nutricionista|Farm\\.?|Farmac[eê]utico)\\s+${escapedVal}`, "i").test(text);
        const temTitulo = temTituloNoValor || temTituloNoTexto;

        const temRegistro = /\b(?:CRM|COREN|CRP|CRO|CRF|CREA|OAB)\b/i.test(text);
        const contextoProfissional = /(?:respons[aá]vel|m[eé]dico\s+respons[aá]vel|encaminhado\s+por|atendido\s+por|laudador|solicitante|profissional)/i.test(text);
        const pareceNome = valor.trim().split(/\s+/).filter(t => t.length > 1).length >= 2;

        if (!pareceNome) continue;

        // No modo balanced/conservative, exige título ou registro ou forte contexto clínico
        if (!temTitulo && !temRegistro && !contextoProfissional) {
          continue;
        }
      }

      // 3. Filtros para TELEFONE
      if (tipo === "TELEFONE") {
        const digitos = valor.replace(/\D/g, "");
        if (digitos.length === 11 && !/[().\-\s]/.test(valor)) continue; // Evita CPF confundido
        if (/^(\d)\1+$/.test(digitos)) continue; // Evita telefones falsos (ex: 999999999)
      }

      // Se passou em todas as regras, adiciona à lista final
      filtered.push(item);
      finalSet.add(dedupeKey);
    }

    // --- COMPILAÇÃO DO RELATÓRIO DE AUDITORIA E ANOMALIAS ---
    const report = this.generateAuditReport(text, filtered, policyMode, explicitPolicy);

    return {
      detections: filtered,
      classificationReport: report
    };
  }

  static generateAuditReport(text, detections, policyMode, explicitPolicy = {}) {
    const maskedCategories = [...new Set(detections.map(d => d.tipo))];

    // Simula o mascaramento do texto substituindo as entidades detectadas por espaços de mesmo comprimento
    const sortedDetections = [...detections].sort((a, b) => b.valor.length - a.valor.length);
    let simulatedText = text;
    for (const d of sortedDetections) {
      if (d.valor) {
        const spaces = " ".repeat(d.valor.length);
        simulatedText = simulatedText.split(d.valor).join(spaces);
      }
    }

    // 1. Identificação de Suspeitas / Anomalias (Dados não mascarados)
    const suspectedUnmaskedItems = [];
    let match;

    // Detecção Programática de CPFs formatados (não mascarados)
    const cpfFormatRegex = /\b\d{3}\.\d{3}\.\d{3}-\d{2}\b/g;
    while ((match = cpfFormatRegex.exec(simulatedText)) !== null) {
      const cpf = match[0];
      if (!suspectedUnmaskedItems.includes(cpf)) {
        suspectedUnmaskedItems.push(cpf);
      }
    }

    // Detecção Programática de CNPJs formatados (não mascarados)
    const cnpjFormatRegex = /\b\d{2}\.\d{3}\.\d{3}\/\d{4}-\d{2}\b/g;
    while ((match = cnpjFormatRegex.exec(simulatedText)) !== null) {
      const cnpj = match[0];
      if (!suspectedUnmaskedItems.includes(cnpj)) {
        suspectedUnmaskedItems.push(cnpj);
      }
    }

    // Detecção Programática de PIS formatados (não mascarados)
    const pisFormatRegex = /\b\d{3}\.\d{5}\.\d{2}-\d{1}\b/g;
    while ((match = pisFormatRegex.exec(simulatedText)) !== null) {
      const pis = match[0];
      if (!suspectedUnmaskedItems.includes(pis)) {
        suspectedUnmaskedItems.push(pis);
      }
    }

    // Detecção Programática de números soltos (possíveis CPFs/Cartões vazados não catalogados) em simulatedText
    // Limite de 16 dígitos para capturar CNPJs (14) ou cartões (16) não formatados
    const numericRegex = /\b(\d{4,16})\b/g;
    while ((match = numericRegex.exec(simulatedText)) !== null) {
      const num = match[1];
      if (!suspectedUnmaskedItems.includes(num)) {
        suspectedUnmaskedItems.push(num);
      }
    }

    // Prepara ignore_list customizada enviada na política
    const ignoreList = new Set(
      Array.isArray(explicitPolicy.ignore_list) 
        ? explicitPolicy.ignore_list.map(w => w.toLowerCase().trim()) 
        : []
    );

    // Detecção de termos capitalizados não catalogados (excluindo início de frases e linhas) em simulatedText
    const lines = simulatedText.split(/[\r\n]+/);
    for (const line of lines) {
      const sentences = line.split(/[.!?]+\s+/);
      for (const sentence of sentences) {
        const words = sentence.split(/[\s,.:;?!()]+/);
        for (let i = 1; i < words.length; i++) {
          const word = words[i];
          // Verifica se começa com maiúscula, tem mais de 2 letras e não é artigo
          if (word.length > 2 && /^[A-ZÀ-Ú][a-zà-ú]+$/.test(word)) {
            const wordLower = word.toLowerCase();
            if (!ARTICLES.has(wordLower) && !ignoreList.has(wordLower)) {
              if (!suspectedUnmaskedItems.includes(word)) {
                suspectedUnmaskedItems.push(word);
              }
            }
          }
        }
      }
    }

    // 2. Cálculo do Risk Score (0 a 100)
    let riskScore = 0;
    // Cada categoria de PII adiciona 20 pontos ao risco (limite de 80)
    riskScore += maskedCategories.length * 20;
    // Presença de suspeitas adiciona risco
    if (suspectedUnmaskedItems.length > 0) {
      riskScore += Math.min(suspectedUnmaskedItems.length * 5, 20);
    }
    riskScore = Math.min(riskScore, 100);

    return {
      masked_categories: maskedCategories,
      suspected_unmasked_items: suspectedUnmaskedItems.slice(0, 10), // Limitado para evitar metadados inflados
      risk_score: riskScore,
      audit_context: {
        has_pii: detections.length > 0,
        policy_mode: policyMode,
        compliance_alert: riskScore >= 70
      }
    };
  }
}
