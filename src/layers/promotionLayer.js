// Promotion Layer: Implementa as regras de promoção contextual de entidades
import { gerarToken } from "../utils/helpers.js";

export class PromotionLayer {
  static async promote(detections, text, strategy) {
    if (!detections || detections.length === 0) {
      return detections;
    }

    const promoted = [...detections];
    const promotedValues = new Set(promoted.map(d => d.valor.toLowerCase()));

    // 1. Promoção: Dr + Nome -> PROFISSIONAL_SAUDE
    // Se houver um NOME_PESSOA detectado que é precedido por Dr/Dra ou similar no texto original
    for (let i = 0; i < promoted.length; i++) {
      const item = promoted[i];
      if (item.tipo === "NOME_PESSOA") {
        const escapedVal = this.escaparRegex(item.valor);
        const prefixRegex = new RegExp(`\\b(?:Dr\\.?a?\\.?|Dra\\.?|Enf\\.?|Enfermeiro|Enfermeira|Fisio\\.?|Psic\\.?|Nutri\\.?)\\s+${escapedVal}`, "i");
        
        if (prefixRegex.test(text)) {
          // Promove a PROFISSIONAL_SAUDE mantendo o original NOME_PESSOA
          const tokenPS = await gerarToken("PROFISSIONAL_SAUDE", item.valor);
          promoted.push({
            tipo: "PROFISSIONAL_SAUDE",
            valor: item.valor,
            token: tokenPS
          });
        }
      }
    }

    // 2. Promoção contextual: IDADE -> DATA_NASCIMENTO (Especificidade UTI Evolução)
    const temIdade = promoted.some(d => d.tipo === "IDADE") || /\b\d{1,3}\s*anos\b/i.test(text);
    const temDN = promoted.some(d => d.tipo === "DATA_NASCIMENTO");
    
    // Heurísticas clínicas de UTI Evolução
    const ehUTIEvolucao = /Subjetivo/i.test(text) && /Horário:\s*\d{2}:\d{2}/i.test(text) && /Neurológico:/i.test(text);
    const ehUTIEnfermagem = /Paciente desperta|Paciente desperto|FC\s+\d+|PA\s+\d+/i.test(text);

    if (strategy.name === "UTI_EVOLUCAO" || (ehUTIEvolucao && !ehUTIEnfermagem && temIdade && !temDN)) {
      const idadeItem = promoted.find(d => d.tipo === "IDADE");
      const valorIdade = idadeItem?.valor || (text.match(/\b\d{1,3}\s*anos\b/i)?.[0]) || "";
      
      if (valorIdade) {
        const tokenDN = await gerarToken("DATA_NASCIMENTO", valorIdade);
        // Só adiciona se não estiver redundante
        if (!promotedValues.has(valorIdade.toLowerCase())) {
          promoted.push({
            tipo: "DATA_NASCIMENTO",
            valor: valorIdade,
            token: tokenDN
          });
          promotedValues.add(valorIdade.toLowerCase());
        }
      }
    }

    // 3. Promoção contextual: idade + contexto (nascimento/nasceu) -> DATA_NASCIMENTO
    // Nota: "nascimento" pode ser sobrenome (ex: "Diego Lopes Nascimento"), então exigimos
    // contexto mais forte: "data de nascimento", "nasceu em", "nasc:" etc.
    const temContextoNascimento = /(?:data\s+de\s+)?nascimento\s*[:=]|nasceu\s+(?:em|no|na|dia)|nasc\s*[:.]|\bdn\s*[:=]/i.test(text);
    if (temIdade && temContextoNascimento && !temDN) {
      const idadeItem = promoted.find(d => d.tipo === "IDADE");
      if (idadeItem) {
        const tokenDN = await gerarToken("DATA_NASCIMENTO", idadeItem.valor);
        // Promove a idade para DATA_NASCIMENTO
        idadeItem.tipo = "DATA_NASCIMENTO";
        idadeItem.token = tokenDN;
      }
    }

    return promoted;
  }

  static escaparRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }
}
