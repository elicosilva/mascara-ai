// Mask Engine: Executa as substituições físicas dos dados pelas tags ⟦PII:TIPO:HASH⟧
import { protegerChavesJSON, restaurarChavesJSON } from "../utils/patterns.js";

export class MaskEngine {
  static mask(text, detections, strategy) {
    if (!text || !detections || detections.length === 0) {
      return text;
    }

    // Protege as chaves JSON antes de fazer substituição no corpo da mensagem
    let maskedText = protegerChavesJSON(text);

    // Ordena as detecções por comprimento do valor em ordem decrescente
    // Isso é vital para que "João Silva" seja mascarado antes de "João"
    const sortedDetections = [...detections].sort((a, b) => b.valor.length - a.valor.length);

    for (const item of sortedDetections) {
      const valor = item.valor;
      const token = item.token;

      // Ignora tokens vazios ou redundantes
      if (!valor || !token) continue;

      // Executa a substituição segura (sem tocar em chaves do JSON estruturado)
      maskedText = this.substituirValoresSeguro(maskedText, valor, token);
    }

    // Restaura as chaves JSON ao formato original
    maskedText = restaurarChavesJSON(maskedText);

    // Remove tags aninhadas que possam ter sido causadas por sobreposição de NER e Regex
    maskedText = maskedText.replace(
      /\u27E6PII:[^\u27E6\u27E7]*\u27E6PII:[A-Z_]+:[0-9A-F]{8}\u27E7[^\u27E6\u27E7]*\u27E7/g,
      (match) => {
        const interno = match.match(/\u27E6PII:[A-Z_]+:[0-9A-F]{8}\u27E7/);
        return interno ? interno[0] : match;
      }
    );

    // Otimização RAG: Sanitização de pontuações órfãs deixadas por remoções no chunk
    if (strategy.sanitizeChunk) {
      maskedText = this.sanitizarChunkRAG(maskedText);
    }

    return maskedText;
  }

  static substituirValoresSeguro(texto, valor, token) {
    const escaped = this.escaparRegex(valor);
    
    // Regex para identificar se o valor é uma chave JSON (ex: "nome": "João" -> não mascarar "nome")
    const regexChave = new RegExp(`"@@KEY_${escaped}@@"\\s*:`, "g");
    if (regexChave.test(texto)) {
      // Se for uma chave, não substitui
      return texto;
    }

    // Substitui todas as ocorrências do valor pelo token
    return texto.split(valor).join(token);
  }

  static sanitizarChunkRAG(texto) {
    return texto
      .replace(/\s+/g, " ")                  // Remove espaços duplicados
      .replace(/\s*,\s*,/g, ",")             // Remove vírgulas duplicadas
      .replace(/\s*,\s*\./g, ".")             // Corrige ponto e vírgula órfã
      .trim();
  }

  static escaparRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }
}
