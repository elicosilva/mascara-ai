import { validarCPF, validarCNPJ, validarPIS, validarCNH } from "./helpers.js";

// Pré-processamento de JSON para evitar que chaves de dicionários sejam confundidas com PII (como nomes próprios)
export function protegerChavesJSON(texto) {
  return texto.replace(
    /"([a-zA-Z_\-][a-zA-Z0-9_\-]{0,59})"(\s*:)/g,
    (match, chave, doispontos) => `"@@KEY_${chave}@@"${doispontos}`
  );
}

export function restaurarChavesJSON(texto) {
  return texto.replace(/"@@KEY_([^@]+)@@"/g, (_, chave) => `"${chave}"`);
}

export const PII_PATTERNS = [
  // ── Cartão de Crédito ───────────────────────────────────────
  { 
    type: "CARTAO",
    regex: /\b(\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4})\b/g,
    validate: () => true 
  },

  // ── IP Address ─────────────────────────────────────────────
  { 
    type: "IP_ADDRESS",
    regex: /(?:x-forwarded-for|x-real-ip|remote.?addr|client.?ip|ip|src|dst)\s*[=:]\s*((?:\d{1,3}\.){3}\d{1,3})/gi,
    validate: (v) => { 
      const ip = v.replace(/.*[=:]\s*/, ""); 
      return ip.split(".").every(n => parseInt(n) <= 255); 
    }
  },
  { 
    type: "IP_ADDRESS",
    regex: /\b((?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b/g,
    validate: (v) => v.split(".").every(n => parseInt(n) <= 255) 
  },

  // ── CHAVE_PIX ──────────────────────────────────────────────
  // Nota: Apenas UUID aleatória é classificada como CHAVE_PIX.
  // CPFs, CNPJs, emails e telefones em contexto Pix são detectados
  // pelos seus respectivos padrões (CPF, CNPJ, EMAIL, TELEFONE).
  { 
    type: "CHAVE_PIX",
    regex: /(?:pix|chave\s+pix)[^\n]{0,30}?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})/gi,
    validate: () => true 
  },

  // ── Telefone contextual ────────────────────────────────────
  { 
    type: "TELEFONE",
    regex: /(?:@@KEY_)?(?:telefone|celular|fone|tel|phone|contato|whatsapp|zap)(?:@@)?"?\s*[=:]\s*"?(\(?\d{2,3}\)?\s?(?:9\s?)?\d{4,5}[\s.\-]?\d{4}|\d{10,11})/gi,
    validate: (v) => {
      const d = v.replace(/\D/g, "");
      if (d.length === 11 && (validarCPF(d) || validarPIS(d) || validarCNH(d))) return false;
      if (d.length === 11 && !/[().\-\s]/.test(v) && (validarCPF(d) || validarPIS(d))) return false;
      return d.length >= 10 && d.length <= 13;
    }
  },

  // ── CPF ────────────────────────────────────────────────────
  { 
    type: "CPF",
    regex: /\b(\d{3}[\s.\-]\d{3}[\s.\-]\d{3}[\s.\-]\d{2})\b/g,
    validate: (v) => { 
      const d = v.replace(/\D/g, ""); 
      return d.length === 11; 
    }
  },
  { 
    type: "CPF",
    regex: /(?:@@KEY_)?(?:cpf|c\.p\.f)(?:@@)?"?\s*[=:é]?\s*"?(\d{3}[\s.\-]?\d{3}[\s.\-]?\d{3}[\s.\-]?\d{2}|\d{11})/gi,
    validate: (v) => { 
      const d = v.replace(/\D/g, ""); 
      return d.length === 11; 
    }
  },

  // ── CNPJ ───────────────────────────────────────────────────
  { 
    type: "CNPJ",
    regex: /\b(\d{2}[\s.\-\/]?\d{3}[\s.\-\/]?\d{3}[\s.\-\/]?\d{4}[\s.\-\/]?\d{2})\b/g,
    validate: (v) => validarCNPJ(v.replace(/\D/g, "")) 
  },

  // ── PIS ────────────────────────────────────────────────────
  { 
    type: "PIS",
    regex: /\b(?<!\d)(\d{3}\.?\d{5}\.?\d{2}-?\d{1})(?!\d)/g,
    validate: (v) => { 
      const d = v.replace(/\D/g, ""); 
      if (d.length !== 11 || v === d) return false; 
      return validarPIS(d); 
    }
  },
  { 
    type: "PIS",
    regex: /(?:["']?(?:@@KEY_)?(?:pis|nis|nit)(?:@@)?["']?\s*[=:"'\s]\s*"?(\d{3}\.?\d{5}\.?\d{2}-?\d{1}|\d{11}))/gi,
    validate: (v) => { 
      const d = v.replace(/\D/g, ""); 
      return d.length === 11 && validarPIS(d); 
    }
  },

  // ── CNH ────────────────────────────────────────────────────
  { 
    type: "CNH",
    regex: /"(?:@@KEY_)?(?:cnh|cnh_numero|habilitac[aã]o|habilitacao|renach|registro)(?:@@)?"\s*:\s*"(\d{11})"/gi,
    validate: (v) => validarCNH(v.replace(/\D/g, "")) 
  },
  { 
    type: "CNH",
    regex: /(?:CNH|Habilitação|RENACH)[^\d]{0,10}(\d{9}[\s.\-]?\d{2})/gi,
    validate: (v) => validarCNH(v.replace(/\D/g, "")) 
  },

  // ── Documentos com prefixos e sufixos agrupados no valor ────
  { 
    type: "RG",
    regex: /(?:RG|R\.G\.|Identidade)[^\d]{0,10}(\d{1,2}[\s.\-]?\d{3}[\s.\-]?\d{3}[\s.\-]?[\dxX])/gi,
    validate: () => true 
  },
  { 
    type: "OAB",
    regex: /\b(OAB[\s\/\-]+[A-Z]{2}[\s\/\-]+\d{4,6})\b/gi,
    validate: () => true 
  },
  { 
    type: "CRM",
    regex: /\b(CRM[\s\/\-]?([A-Z]{2})?[\s\/\-]?\d{4,7}|\bCRM[\s\/\-]?\d{4,7}[\s\/\-]?([A-Z]{2})?)\b/gi,
    validate: () => true 
  },
  { 
    type: "CREA",
    regex: /\b(CREA[\s\/\-]?[A-Z]{2}[\s\/\-]?\d{5,9}(?:\-\d)?)\b/gi,
    validate: () => true 
  },
  {
    type: "COREN",
    regex: /\b(COREN(?:[\s\/\-]?[A-Z]{2})?(?:\s*(?:n[ºo°]\.?|:|-))?\s*\d{4,9}(?:[\s\/\-]?[A-Z]{2})?)\b/gi,
    validate: (v) => {
      const n = v.replace(/\D/g, "");
      return n.length >= 4 && n.length <= 9;
    }
  },
  { 
    type: "CRO",
    regex: /\b(CRO[\s\/\-]?[A-Z]{2}[\s\/\-]?\d{4,7})\b/gi,
    validate: () => true 
  },
  { 
    type: "CRF",
    regex: /\b(CRF[\s\/\-?[A-Z]{2}[\s\/\-]?\d{4,7})\b/gi,
    validate: () => true 
  },
  { 
    type: "CRP",
    regex: /\b(CRP[\s\/\-]?\d{2}\/\d{4,6})\b/gi,
    validate: () => true 
  },

  // ── Contato ────────────────────────────────────────────────
  { 
    type: "EMAIL",
    regex: /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g,
    validate: () => true 
  },
  { 
    type: "TELEFONE",
    regex: /(?<!\d)(\(?\d{2,3}\)?\s?(?:9\s?)?\d{4}[\s.\-]?\d{3,4})(?!\d)/g,
    validate: (v) => {
      const d = v.replace(/\D/g, "");
      if (d.length >= 10 && /^(\d)\1+$/.test(d)) return false;
      if (d.length === 11 && !v.includes("(") && !v.includes(")") && (validarCPF(d) || validarPIS(d) || validarCNH(d))) return false;
      if (d.length === 11 && !/[().\-\s]/.test(v)) return false;
      return d.length >= 10 && d.length <= 13;
    }
  },
  {
    type: "TELEFONE",
    regex: /(?:Contato|Tel|Telefone)\s*[:\-]?\s*(\(?\d{2}\)?\s?9?\d{4,5}[\- ]?\d{4})/gi,
    validate: (v) => {
      const d = v.replace(/\D/g, "");
      return d.length >= 10;
    }
  },

  // ── Dados temporais ────────────────────────────────────────
  {
    type: "DATA_NASCIMENTO",
    regex: /(?:nascimento|nasceu|data\s+de\s+nascimento|d\.?n\.?|nasc\.?)\D{0,15}(\d{2}[\/\-]\d{2}[\/\-]\d{4})/gi,
    validate: (v) => {
      const data = (v || "").match(/\d{2}[\/\-]\d{2}[\/\-]\d{4}/);
      if (!data) return false;
      const [dia, mes, ano] = data[0].split(/[\/\-]/).map(Number);
      return dia >= 1 && dia <= 31 && mes >= 1 && mes <= 12 && ano >= 1900 && ano <= 2099;
    }
  },
  { 
    type: "DATA_NASCIMENTO",
    regex: /(?:Nasc\.|D\.?N\.?)[:\s]+(\d{2}[\/\-]\d{2}[\/\-]\d{4})/gi,
    validate: (v) => {
      const data = (v || "").match(/\d{2}[\/\-]\d{2}[\/\-]\d{4}/);
      if (!data) return false;
      const [dia, mes, ano] = data[0].split(/[\/\-]/).map(Number);
      return dia >= 1 && dia <= 31 && mes >= 1 && mes <= 12 && ano >= 1900 && ano <= 2099;
    }
  },
  { 
    type: "CEP",
    regex: /\b(\d{5}-\d{3})\b/g,
    validate: () => true 
  },

  // ── Prontuário Clínico ─────────────────────────────────────
  { 
    type: "PRONTUARIO",
    regex: /(?:@@KEY_)?(?:prontuario|prontu[aá]rio|pront|pron|prt|prn)(?:@@)?"?[^0-9\n]{0,15}?[=::#nº°\s]{1,5}"?(\d{4,8})/gi,
    validate: () => true 
  },

  // ── Profissionais de Saúde ──────────────────────────────────
  { 
    type: "PROFISSIONAL_SAUDE",
    regex: /\b((?:[dD][rR][aA]?\.?|[eE][nN][fF]\.?|[eE]nfermeir[oa]|[fF]isio\.?|[pP]sic\.?|[nN]utri\.?|[fF]arm\.?)\s+[A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+(?:[ \t]+[A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+){0,3})/g,
    validate: (v) => v.trim().split(/\s+/).length >= 2 
  },
  { 
    type: "PROFISSIONAL_SAUDE",
    regex: /(?:[rR]espons[aá]vel|[mM][eé]dico\s+[rR]espons[aá]vel|[eE]ncaminhado\s+por|[aA]tendido\s+por)[^:\n]{0,20}:\s*([dD][rR][aA]?\.?\s+[A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+(?:[ \t]+[A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+){0,3})/g,
    validate: (v) => v.trim().split(/\s+/).length >= 2 
  },

  // ── Idade ──────────────────────────────────────────────────
  { 
    type: "IDADE",
    regex: /\b(\d{1,3}\s+anos?)\b/gi,
    validate: (v) => { 
      const n = parseInt(v); 
      return n >= 1 && n <= 120; 
    }
  },

  // ── Filiação ───────────────────────────────────────────────
  { 
    type: "NOME_MAE",
    regex: /(?:@@KEY_)?(?:[nN]ome\s+da?\s+m[ãa]e|[mM]ãe|MÃE|[mM]other|[gG]enitora|[fF]ilho\(a\)\s+de|[fF]ilho\s+de|[fF]ilha\s+de|[rR]espons[aá]vel|RESPONSÁVEL)(?:\/[^:={}\n]{1,20})?(?:@@)?"?\s*[=:\-\s]{1,5}"?([A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+(?:[ \t]+(?:da?|de|do|das|dos|e)?[ \t]*[A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+){1,4})/g,
    validate: (v) => v.trim().split(/\s+/).filter(p => p.length > 1).length >= 2 
  },
  { 
    type: "NOME_MAE",
    regex: /\b(?:M[ãa]e|MÃE):\s*([A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+(?:[ \t]+(?:da?|de|do|das|dos|e)?[ \t]*[A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+){0,3})/g,
    validate: (v) => v.trim().split(/\s+/).filter(p => p.length > 1).length >= 2 
  },
  { 
    type: "NOME_PAI",
    regex: /(?:@@KEY_)?(?:[nN]ome\s+do?\s+pai|[pP]ai|[fF]ather|[gG]enitor|[fF]ilho\(a\)\s+de|[fF]ilho\s+de|[fF]ilha\s+de)(?:@@)?"?\s*[=:\-\s]{1,5}"?([A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+(?:[ \t]+(?:da?|de|do|das|dos|e)?[ \t]*[A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+){1,4})/g,
    validate: (v) => v.trim().split(/\s+/).filter(p => p.length > 1).length >= 2 
  },
  { 
    type: "NOME_PAI",
    regex: /\bPai:\s*([A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+(?:[ \t]+(?:da?|de|do|das|dos|e)?[ \t]*[A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+){0,3})/g,
    validate: (v) => v.trim().split(/\s+/).filter(p => p.length > 1).length >= 2 
  },
  
  // ── Nomes Próprios ──────────────────────────────────────────
  {
    type: "NOME_PESSOA",
    regex: /\bRN\s+(?:de\s+)?([A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+(?:[ \t]+(?:da?|de|do|das|dos|e)?[ \t]*[A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+){1,4})/g,
    validate: (v) => v.trim().split(/\s+/).filter(p => p.length > 1).length >= 2
  },
  { 
    type: "NOME_PESSOA",
    regex: /(?:[mM]e\s+chamo|[cC]hamo\s+me\s+de|[sS]ou|[mM]eu\s+nome\s+(?:completo\s+)?é\s+|[nN]ome\s+é\s+|[cC]hama\s+se\s+|[eE]u\b,?\s+)\s*([A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+(?:[ \t]+(?:da?|de|do|das|dos|e)?[ \t]*[A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+){1,4})/g,
    validate: (v) => v.trim().split(/\s+/).filter(p => p.length > 1).length >= 2 
  },
  {
    type: "NOME_PESSOA",
    regex: /\b(?:[sS][rR]\.?|[sS][rR][aA]\.?)\s+([A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+(?:[ \t]+(?:da?|de|do|das|dos|e)?[ \t]*[A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+){1,4})/g,
    validate: (v) => v.trim().split(/\s+/).length >= 2
  },
  { 
    type: "NOME_PESSOA",
    regex: /[pP][aA][cC][iI][eE][nN][tT][eE]:\s*([A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+(?:[ \t]+(?:da?|de|do|das|dos|e)?[ \t]*[A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+){1,4})(?:\s*[|\n,]|$)/g,
    validate: (v) => v.trim().split(/\s+/).filter(p => p.length > 1).length >= 2 
  },
  {
    type: "NOME_PESSOA",
    regex: /^\s*\d+\s+[A-Z]\s*-\s*([A-ZÀ-ÚÇÜ][A-ZÀ-ÚÇÜa-zà-úçü]+(?:[ \t]+[A-ZÀ-ÚÇÜ][A-ZÀ-ÚÇÜa-zà-úçü]+){1,4})(?=,\s*\d+\s+anos)/gm,
    validate: (v) => v.trim().split(/\s+/).length >= 2
  },
  { 
    type: "NOME_PESSOA",
    regex: /(?:["']?(?:@@KEY_)?(?:[nN]ome|NOME|[nN]ame|NAME|[uU]ser_[nN]ame|USER_NAME|[uU]ser|USER|[tT]arget_[nN]ome|[tT]arget_[nN]ame|TARGET_NAME|TARGET_NOME|[oO]perator|OPERATOR|[tT]itular|TITULAR|[cC]liente|CLIENTE|[pP]aciente|PACIENTE|[pP]cte|PCTE|[pP]ct|PCT|[iI]dentifica[çc][ãa]o|IDENTIFICA[ÇC][ÃA]O|[iI]dent|IDENT|[bB]enefici[aá]rio|BENEFICI[AÁ]RIO|[rR]espons[aá]vel|RESPONS[AÁ]VEL|[fF]uncion[aá]rio|FUNCION[AÁ]RIO|[mM]otorista|MOTORISTA|[vV]endedor|VENDEDOR|[cC]ontato|CONTATO|[fF]ornecedor|FORNECEDOR|[cC]riado_por|CRIADO_POR|[lL]ocat[aá]rio|LOCAT[AÁ]RIO|[rR]ecebedor|RECEBEDOR|[fF]avorecido|FAVORECIDO|[rR]emetente|REMETENTE|[cC]ontratante|CONTRATANTE|[cC]ontratado|CONTRATADO|[cC]omprador|COMPRADOR|[dD]estinat[aá]rio|DESTINAT[AÁ]RIO|[sS]olicitante|SOLICITANTE|[dD]enunciante|DENUNCIANTE|[aA]utor|AUTOR|[rR]equerente|REQUERENTE|[cC]rian[cç]a|CRIAN[CÇ]A)(?:@@)?["']?\s*(?:\.\s*)?[=:"'\s])\s*["']?([A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+(?:[ \t]+(?:da?|de|do|das|dos|e)?[ \t]*[A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+){1,4})/g,
    validate: (v) => v.trim().split(/\s+/).filter(p => p.length > 1).length >= 2 
  },
  {
    type: "NOME_PESSOA",
    regex: /[nN][oO][mM][eE]\s*:\s*([A-ZÀ-ÚÇÜ][A-ZÀ-ÚÇÜa-zà-úçü]+(?:[ \t]+[A-ZÀ-ÚÇÜ][A-ZÀ-ÚÇÜa-zà-úçü]+){1,4})/g,
    validate: (v) => v.trim().split(/\s+/).length >= 2
  },
  // Paciente + Nome + , + N anos
  {
    type: "NOME_PESSOA",
    regex: /[pP][aA][cC][iI][eE][nN][tT][eE]\s+([A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+(?:[ \t]+[A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+){1,4})(?=,\s*\d+\s+anos)/gi,
    validate: (v) => v.trim().split(/\s+/).length >= 2
  },
  // Paciente + Nome + , + CPF/DN (sem colon)
  {
    type: "NOME_PESSOA",
    regex: /[pP][aA][cC][iI][eE][nN][tT][eE]\s+([A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+(?:[ \t]+(?:da?|de|do|e)?[ \t]*[A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+){1,4})(?=,\s*(?:CPF|DN|data|telefone|nascimento|portador))/gi,
    validate: (v) => v.trim().split(/\s+/).filter(p => p.length > 1).length >= 2
  },
  // "consulta para NomeSobrenome" (ex: Confirmamos agendamento de consulta para ...)
  // Uses 'para' as the anchor word directly before the name
  {
    type: "NOME_PESSOA",
    regex: /(?:consulta|agendamento|atendimento|procedimento|exame|cirurgia|interna[çc][ãa]o)[^.]{0,30}?\bpara\s+([A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+(?:[ \t]+(?:da?|de|do|e)?[ \t]*[A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+){1,4})(?=,|\s*CPF|\s*\.|$)/gi,
    validate: (v) => v.trim().split(/\s+/).filter(p => p.length > 1).length >= 2
  },
  // "consultor independente NomeSobrenome" / "consultor NomeSobrenome"
  {
    type: "NOME_PESSOA",
    regex: /(?:[cC]onsultor(?:\s+[iI]ndependente)?|[rR]epresentante|[pP]rocurador|[aA]dvogado|[fF]iador|[aA]valista|[lL]ocador|[pP]ropriet[aá]rio|[iI]nquilino|[mM]utu[aá]rio|[cC]edente|[cC]ession[aá]rio|[oO]utorgado|[oO]utorgante|[tT]estemunha|[pP]erito)\s+([A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+(?:[ \t]+(?:da?|de|do|e)?[ \t]*[A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+){1,4})(?=,|\.|\s*portador|\s*CPF|$)/g,
    validate: (v) => v.trim().split(/\s+/).filter(p => p.length > 1).length >= 2
  },
  // Logs: name='Nome Sobrenome' or name="Nome Sobrenome"
  {
    type: "NOME_PESSOA",
    regex: /\bname=['"]([A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+(?:[ \t]+(?:da?|de|do|e)?[ \t]*[A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+){1,4})['"]?/gi,
    validate: (v) => v.trim().split(/\s+/).filter(p => p.length > 1).length >= 2
  },
  // Reembolso/Transferência: "Recebedor: Nome" or "Favorecido: Nome" (standalone, not in JSON)
  {
    type: "NOME_PESSOA",
    regex: /(?:[rR]ecebedor|[fF]avorecido|[tT]itular|[lL]ocat[aá]rio|[rR]emetente|[cC]ontratante|[dD]estinat[aá]rio|[sS]olicitante)[^:]{0,10}:\s*([A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+(?:[ \t]+(?:da?|de|do|das|dos|e)?[ \t]*[A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+){1,4})/g,
    validate: (v) => v.trim().split(/\s+/).filter(p => p.length > 1).length >= 2
  },
  // "Nome do remetente: Nome" pattern
  {
    type: "NOME_PESSOA",
    regex: /[nN]ome\s+d[oae]\s+(?:remetente|contato|titular|cliente|paciente|benefici[aá]rio|respons[aá]vel|usu[aá]rio|locat[aá]rio|comprador)\s*:\s*([A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+(?:[ \t]+(?:da?|de|do|das|dos|e)?[ \t]*[A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+){1,4})/g,
    validate: (v) => v.trim().split(/\s+/).filter(p => p.length > 1).length >= 2
  },
  // "portador do CPF" preceded by a name
  {
    type: "NOME_PESSOA",
    regex: /(?:entre[^,]{0,30}?(?:e\s+o|o)\s+(?:consultor|representante|contratado|sr\.?|sra\.?)\s+(?:independente\s+)?)([A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+(?:[ \t]+(?:da?|de|do|e)?[ \t]*[A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+){1,4})(?=,|\s*portador)/gi,
    validate: (v) => v.trim().split(/\s+/).filter(p => p.length > 1).length >= 2
  },
  // Closing signature: "Atenciosamente, Nome Sobrenome"
  {
    type: "NOME_PESSOA",
    regex: /(?:Atenciosamente|Cordialmente|Abraços|Respeitosamente|Att|Grato|Grata|Obrigado|Obrigada)[.,]?\s*\n?\s*([A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+(?:[ \t]+(?:da?|de|do|e)?[ \t]*[A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜ][A-ZÀÁÂÃÉÊÍÓÔÕÚÇÜa-záàâãéêíóôõúçü]+){1,4})(?:[.\n,]|$)/gi,
    validate: (v) => v.trim().split(/\s+/).filter(p => p.length > 1).length >= 2
  },

  // ── Endereço Residencial ────────────────────────────────────
  {
    type: "ENDERECO_RESIDENCIAL",
    regex: /(?:residente\s+[àaáo]\s+|(?:endere[çc]o|end\.?)(?:\s+familiar)?\s*[:\-]?\s*)((?:Rua|Av\.?|Avenida|Alameda|Al\.?|Travessa|Trav\.?|Estrada|Rod\.?|Rodovia|Vila|Jardim|Praça|Pça\.?)\s+(?:(?!\b(?:tel|telefone|cel|celular|contato|fone)\b)[^|\n]){10,150}?\b\d{5}-\d{3})/gi,
    validate: (v) => v.trim().length >= 15
  },
  {
    type: "ENDERECO_RESIDENCIAL",
    regex: /(?:residente\s+[àaáo]\s+|(?:endere[çc]o|end\.?)(?:\s+familiar)?\s*[:\-]?\s*)((?:Rua|Av\.?|Avenida|Alameda|Al\.?|Travessa|Trav\.?|Estrada|Rod\.?|Rodovia|Vila|Jardim|Praça|Pça\.?)\s+(?:(?!\b(?:tel|telefone|cel|celular|contato|fone)\b)[^|\n.]){10,120})/gi,
    validate: (v) => v.trim().length >= 10
  },
  {
    type: "ENDERECO_RESIDENCIAL",
    regex: /(?:@@KEY_)?(?:logradouro|endere[çc]o)(?:@@)?"?\s*[=:]\s*"?([^"{\n,\]]{6,120}?)(?="|,\s*"|\}|$)/gi,
    validate: (v) => v.trim().length >= 5
  },
  { 
    type: "ENDERECO_RESIDENCIAL",
    regex: /\b((?:Rua|Av\.?|Avenida|Alameda|Al\.?|Travessa|Trav\.?|Estrada|Rod\.?|Rodovia|Vila|Jardim|Praça|Pça\.?)\s+[A-ZÀ-Úa-zà-ú][A-ZÀ-Úa-zà-ú\s]{3,50}(?:[,\s]+\d{1,5})?)/g,
    validate: (v) => v.trim().length >= 8 
  }
];
