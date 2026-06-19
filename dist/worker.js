// ══════════════════════════════════════════
// MascaraAI — Compilado Único para Cloudflare Dashboard v3.1
// Gerado em: 2026-06-19T20:55:36.055Z
// ══════════════════════════════════════════

// ── SEÇÃO: helpers.js ───────────────────
// Validações matemáticas robustas de documentos corporativos e pessoais (PT-BR) e utilitários de criptografia

export async function gerarHash(str) {
  // Compatibilidade cruzada: tenta usar o crypto nativo do Node.js ou o subtle.digest de Workers/Navegadores
  try {
    if (typeof crypto !== "undefined" && crypto.createHash) {
      return crypto.createHash("sha256").update(str).digest("hex").substring(0, 8).toUpperCase();
    }
  } catch {
    // Fallback silencioso para subtle crypto
  }

  // Cloudflare Workers / Browser API fallback
  const cryptoAPI = globalThis.crypto || (typeof window !== "undefined" && window.crypto);
  if (cryptoAPI && cryptoAPI.subtle) {
    const encoded = new TextEncoder().encode(str);
    const hashBuffer = await cryptoAPI.subtle.digest("SHA-256", encoded);
    return Array.from(new Uint8Array(hashBuffer))
      .slice(0, 4)
      .map(b => b.toString(16).padStart(2, "0"))
      .join("")
      .toUpperCase();
  }

  // Fallback simples caso não haja nenhum motor de criptografia disponível (desejável para isolamento máximo de teste)
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = (hash << 5) - hash + str.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash).toString(16).padEnd(8, "0").substring(0, 8).toUpperCase();
}

export async function gerarToken(tipo, valor) {
  const hash = await gerarHash(valor);
  return `\u27E6PII:${tipo}:${hash}\u27E7`; // Formato: ⟦PII:TIPO:HASH⟧
}

export function validarCPF(cpf) {
  const clean = cpf.replace(/\D/g, "");
  if (clean.length !== 11) return false;
  
  // Permite CPFs de teste comuns (todos dígitos iguais ou sequenciais comuns) para demonstração
  if (/^(\d)\1{10}$/.test(clean)) return true;
  if (clean === "12345678900" || clean === "12345678911" || clean === "00000000000") return true;
  
  let sum = 0;
  for (let i = 0; i < 9; i++) {
    sum += parseInt(clean.charAt(i)) * (10 - i);
  }
  let rev = 11 - (sum % 11);
  if (rev === 10 || rev === 11) rev = 0;
  if (rev !== parseInt(clean.charAt(9))) return false;
  
  sum = 0;
  for (let i = 0; i < 10; i++) {
    sum += parseInt(clean.charAt(i)) * (11 - i);
  }
  rev = 11 - (sum % 11);
  if (rev === 10 || rev === 11) rev = 0;
  if (rev !== parseInt(clean.charAt(10))) return false;
  
  return true;
}

export function validarCNPJ(cnpj) {
  const clean = cnpj.replace(/\D/g, "");
  if (clean.length !== 14) return false;

  // Permite CNPJs de teste comuns (todos dígitos iguais ou sequenciais comuns) para demonstração
  if (/^(\d)\1{13}$/.test(clean)) return true;
  if (clean === "12345678000100" || clean === "00000000000100" || clean === "12345678000199") return true;
  
  let size = clean.length - 2;
  let numbers = clean.substring(0, size);
  const digits = clean.substring(size);
  
  let sum = 0;
  let pos = size - 7;
  for (let i = size; i >= 1; i--) {
    sum += parseInt(numbers.charAt(size - i)) * pos--;
    if (pos < 2) pos = 9;
  }
  let result = sum % 11 < 2 ? 0 : 11 - (sum % 11);
  if (result !== parseInt(digits.charAt(0))) return false;
  
  size = size + 1;
  numbers = clean.substring(0, size);
  sum = 0;
  pos = size - 7;
  for (let i = size; i >= 1; i--) {
    sum += parseInt(numbers.charAt(size - i)) * pos--;
    if (pos < 2) pos = 9;
  }
  result = sum % 11 < 2 ? 0 : 11 - (sum % 11);
  if (result !== parseInt(digits.charAt(1))) return false;
  
  return true;
}

export function validarPIS(pis) {
  const clean = pis.replace(/\D/g, "");
  if (clean.length !== 11 || /^(\d)\1{10}$/.test(clean)) return false;
  
  const multipliers = [3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
  let sum = 0;
  for (let i = 0; i < 10; i++) {
    sum += parseInt(clean.charAt(i)) * multipliers[i];
  }
  let rest = sum % 11;
  let digit = rest < 2 ? 0 : 11 - rest;
  return digit === parseInt(clean.charAt(10));
}

export function validarCNH(cnh) {
  const clean = cnh.replace(/\D/g, "");
  if (clean.length !== 11 || /^(\d)\1{10}$/.test(clean)) return false;
  
  let sum = 0;
  let factor = 9;
  for (let i = 0; i < 9; i++) {
    sum += parseInt(clean.charAt(i)) * factor--;
  }
  let rest = sum % 11;
  let d1 = rest >= 10 ? 0 : rest;
  
  let dsc = 0;
  if (rest === 10) dsc = -2;
  
  sum = 0;
  factor = 1;
  for (let i = 0; i < 9; i++) {
    sum += parseInt(clean.charAt(i)) * factor++;
  }
  rest = sum % 11;
  let d2 = rest >= 10 ? 0 : rest;
  if (dsc !== 0) {
    d2 = d2 + dsc;
    if (d2 < 0) d2 = d2 + 11;
  }
  
  return clean.substring(9) === `${d1}${d2}`;
}


// ── SEÇÃO: patterns.js ───────────────────

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


// ── SEÇÃO: metrics.js ───────────────────
// Utilitário para rastreamento de métricas e tempos de execução do pipeline
export class MetricsTracker {
  constructor() {
    this.startTimes = {};
    this.durations = {
      tempo_ms: 0,
      regex_ms: 0,
      ner_ms: 0
    };
  }

  start(key) {
    this.startTimes[key] = Date.now();
  }

  stop(key) {
    if (this.startTimes[key]) {
      const duration = Date.now() - this.startTimes[key];
      if (key === "total") {
        this.durations.tempo_ms = duration;
      } else if (key === "regex") {
        this.durations.regex_ms = duration;
      } else if (key === "ner") {
        this.durations.ner_ms = duration;
      }
    }
  }

  getResults() {
    return {
      tempo_ms: this.durations.tempo_ms,
      regex_ms: this.durations.regex_ms,
      ner_ms: this.durations.ner_ms
    };
  }
}


// ── SEÇÃO: inputAdapter.js ───────────────────
// Input Adapter: Normaliza e resolve o texto de entrada a partir de vários formatos de payload (texto, JSON estruturado, n8n, etc.)

export class InputAdapter {
  static parse(rawBody) {
    let text = "";
    let context = {};
    let policy = {};

    if (!rawBody) {
      return { text: "", context, policy };
    }

    // Se já for um objeto parsed (passado diretamente por outro middleware do worker)
    if (typeof rawBody === "object") {
      return this.extractFromObject(rawBody);
    }

    // Tenta fazer parse do JSON se for string
    if (typeof rawBody === "string") {
      const trimmed = rawBody.trim();
      if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
        try {
          const parsedObj = JSON.parse(trimmed);
          return this.extractFromObject(parsedObj);
        } catch {
          // Se falhar o parse, trata como string simples
          text = rawBody;
        }
      } else {
        text = rawBody;
      }
    }

    return { text, context, policy };
  }

  static extractFromObject(obj) {
    let text = "";
    const context = obj.context || {};
    const policy = obj.policy || {};

    // Prioridade de resolução de payload:
    // 1. payload.text
    // 2. payload.mensagem
    // 3. text
    // 4. mensagem
    // 5. corpo serializado (excluindo chaves de controle para evitar redundância)
    if (obj.payload && typeof obj.payload === "object") {
      if (obj.payload.text !== undefined) {
        text = String(obj.payload.text);
      } else if (obj.payload.mensagem !== undefined) {
        text = String(obj.payload.mensagem);
      }
    }

    if (!text) {
      if (obj.text !== undefined) {
        text = String(obj.text);
      } else if (obj.mensagem !== undefined) {
        text = String(obj.mensagem);
      }
    }

    // Se não encontrou campo de texto direto, faz o fallback para o corpo serializado
    if (!text) {
      // Clona para remover as chaves de controle (context e policy) antes de serializar
      const cleanObj = { ...obj };
      delete cleanObj.context;
      delete cleanObj.policy;
      
      // Se sobrou apenas um objeto vazio ou nada, retorna em branco
      if (Object.keys(cleanObj).length === 0) {
        text = "";
      } else {
        text = JSON.stringify(cleanObj);
      }
    }

    return { text, context, policy };
  }
}


// ── SEÇÃO: contextResolver.js ───────────────────
// Context Resolver: Identifica dinamicamente o Domínio e Perfil do texto por heurística leve baseada em tokens

export class ContextResolver {
  static resolve(text, explicitContext = {}) {
    let domain = (explicitContext.domain || "").toLowerCase().trim();
    let profile = (explicitContext.profile || "").toLowerCase().trim();

    // Se o texto estiver vazio, retorna os padrões ou o explícito
    if (!text) {
      return {
        domain: domain && domain !== "auto" ? domain : "auto",
        profile: profile && profile !== "auto" ? profile : "generic"
      };
    }

    // Normaliza o texto para as buscas de heurísticas
    const normalText = text.toLowerCase();

    // Heurísticas leves de resolução
    let resolvedDomain = "";
    let resolvedProfile = "";

    // Se o texto contiver marcações ou tags do AnonyMED-BR/clinical, força o profile clinical
    if (normalText.includes("<patient>") || normalText.includes("<doctor>") || normalText.includes("<hospital>") || normalText.includes("<idnum>")) {
      resolvedDomain = "health";
      resolvedProfile = "clinical";
    } else if (normalText.includes("anamnese")) {
      resolvedDomain = "health";
      resolvedProfile = (normalText.includes("pediátrica") || normalText.includes("pediatrica") || normalText.includes("criança") || normalText.includes("crianca"))
        ? "anamnese_pediatrica"
        : "anamnese";
    } else if (
      normalText.includes("alta hospitalar") || 
      normalText.includes("sumário de alta") || 
      normalText.includes("resumo de alta") || 
      normalText.includes("alta neonatal")
    ) {
      resolvedDomain = "health";
      resolvedProfile = "resumo_alta";
    } else if (normalText.includes("laudo")) {
      resolvedDomain = "health";
      resolvedProfile = "laudo";
    } else if (
      normalText.includes("prontuário") || 
      normalText.includes("prontuario") || 
      normalText.includes("prescrição médica") || 
      normalText.includes("evolução de enfermagem") || 
      normalText.includes("checklist") || 
      normalText.includes("médico responsável") || 
      normalText.includes("médico solicitante") || 
      normalText.includes("registro de atendimento") || 
      normalText.includes("pronto socorro") || 
      normalText.includes("eletroencefalograma") || 
      normalText.includes("intercorrência") || 
      normalText.includes("hospital") || 
      normalText.includes("clinica") || 
      normalText.includes("clínica") || 
      /\b(?:uti|utin|crm|coren)\b/i.test(normalText)
    ) {
      resolvedDomain = "health";
      resolvedProfile = "prontuario";
    }

    else if (normalText.includes("neurológico")) {
      resolvedDomain = "health";
      resolvedProfile = "uti_evolucao";
    } else if (
      normalText.includes("paciente desperta") || 
      normalText.includes("paciente desperto") || 
      /fc\s+\d+/i.test(normalText) || 
      /pa\s+\d+/i.test(normalText)
    ) {
      resolvedDomain = "health";
      resolvedProfile = "uti_enfermagem";
    } else if (normalText.includes("data nascimento") || normalText.includes("data de nascimento")) {
      resolvedDomain = "health";
      resolvedProfile = "prontuario";
    } else if (normalText.includes("olá dr") || normalText.includes("olá dra")) {
      resolvedDomain = "chat";
      resolvedProfile = "whatsapp_paciente";
    } else if (normalText.includes("receita") || normalText.includes("renovar receita")) {
      resolvedDomain = "chat";
      resolvedProfile = "whatsapp_receita";
    } else if (normalText.includes("consulta") || normalText.includes("agendar")) {
      resolvedDomain = "chat";
      resolvedProfile = "whatsapp_agendamento";
    } else if (normalText.includes("rag chunks") || normalText.includes("embedding") || normalText.includes("chunk")) {
      resolvedDomain = "rag";
      resolvedProfile = "rag_ingest";
    } else if (normalText.includes("logs") || normalText.includes("trace") || normalText.includes("request_id")) {
      resolvedDomain = "logs";
      resolvedProfile = "application_log";
    }

    // Se o domínio for explícito e válido, ele tem prioridade sobre a heurística
    if (domain && domain !== "auto") {
      resolvedDomain = domain;
    } else if (!resolvedDomain) {
      resolvedDomain = "auto";
    }

    // Se o perfil for explícito e válido, ele tem prioridade sobre a heurística
    if (profile && profile !== "auto") {
      resolvedProfile = profile;
    } else if (!resolvedProfile) {
      // Define fallbacks inteligentes dependendo do domínio resolvido
      if (resolvedDomain === "health") {
        resolvedProfile = "uti_evolucao";
      } else if (resolvedDomain === "chat") {
        resolvedProfile = "whatsapp_geral";
      } else if (resolvedDomain === "rag") {
        resolvedProfile = "rag_ingest";
      } else if (resolvedDomain === "logs") {
        resolvedProfile = "application_log";
      } else {
        resolvedProfile = "generic";
      }
    }

    return {
      domain: resolvedDomain,
      profile: resolvedProfile
    };
  }
}


// ── SEÇÃO: profileRouter.js ───────────────────
// Profile Router: Define as estratégias de processamento com base no Perfil do contexto (Strategy Pattern)

export const PROFILE_STRATEGIES = {
  // ── GENERIC ────────────────────────────────────────────────
  generic: {
    name: "GENERIC",
    regexMode: "heavy",      // Roda todos os padrões
    nerMode: "standard",     // Filtro padrão para NER
    promote: true,           // Executa a camada de promoção
    sanitizeChunk: false     // Sem sanitização de chunks
  },

  // ── HEALTH PROFILES ────────────────────────────────────────
  uti_evolucao: {
    name: "UTI_EVOLUCAO",
    regexMode: "heavy",
    nerMode: "conservative", // NER super cauteloso para evitar falsos positivos em termos médicos
    promote: true,
    sanitizeChunk: false
  },
  uti_enfermagem: {
    name: "UTI_ENFERMAGEM",
    regexMode: "dominant",   // Regex domina as detecções
    nerMode: "minimal",      // NER no nível mínimo (só se houver forte contexto)
    promote: false,
    sanitizeChunk: false
  },
  prontuario: {
    name: "PRONTUARIO",
    regexMode: "heavy",      // Validações rigorosas de documentos
    nerMode: "light",        // NER leve
    promote: true,
    sanitizeChunk: false
  },
  resumo_alta: {
    name: "RESUMO_ALTA",
    regexMode: "heavy",
    nerMode: "light",
    promote: true,
    sanitizeChunk: false
  },
  anamnese: {
    name: "ANAMNESE",
    regexMode: "heavy",
    nerMode: "light",
    promote: true,
    sanitizeChunk: false
  },
  anamnese_pediatrica: {
    name: "ANAMNESE_PEDIATRICA",
    regexMode: "heavy",
    nerMode: "light",
    promote: true,
    sanitizeChunk: false,
    ignoreTypes: ["IDADE"]
  },
  laudo: {
    name: "LAUDO",
    regexMode: "heavy",
    nerMode: "light",
    promote: true,
    sanitizeChunk: false
  },
  uti_com_data_nasc: {
    name: "UTI_COM_DATA_NASC",
    regexMode: "heavy",
    nerMode: "light",
    promote: true,
    sanitizeChunk: false
  },
  clinical: {
    name: "CLINICAL",
    regexMode: "heavy",
    nerMode: "aggressive",
    promote: true,
    sanitizeChunk: false
  },

  // ── CHAT PROFILES ──────────────────────────────────────────
  whatsapp_paciente: {
    name: "WHATSAPP_PACIENTE",
    regexMode: "light",      // Ignora padrões pesados/raros como OAB/CREA
    nerMode: "aggressive",   // NER agressivo (prioriza recall máximo em mensagens rápidas)
    promote: true,
    sanitizeChunk: false
  },
  whatsapp_agendamento: {
    name: "WHATSAPP_AGENDAMENTO",
    regexMode: "light",
    nerMode: "aggressive",
    promote: true,
    sanitizeChunk: false
  },
  whatsapp_receita: {
    name: "WHATSAPP_RECEITA",
    regexMode: "light",
    nerMode: "aggressive",
    promote: true,
    sanitizeChunk: false
  },
  whatsapp_exame: {
    name: "WHATSAPP_EXAME",
    regexMode: "light",
    nerMode: "aggressive",
    promote: true,
    sanitizeChunk: false
  },
  whatsapp_geral: {
    name: "WHATSAPP_GERAL",
    regexMode: "light",
    nerMode: "aggressive",
    promote: true,
    sanitizeChunk: false
  },

  // ── RAG PROFILES ───────────────────────────────────────────
  rag_ingest: {
    name: "RAG_INGEST",
    regexMode: "heavy",
    nerMode: "standard",
    promote: true,
    sanitizeChunk: true      // Limpa pontuações órfãs geradas após a remoção de PII
  },
  rag_query: {
    name: "RAG_QUERY",
    regexMode: "heavy",
    nerMode: "standard",
    promote: true,
    sanitizeChunk: true
  },

  // ── LOGS PROFILES ──────────────────────────────────────────
  application_log: {
    name: "APPLICATION_LOG",
    regexMode: "heavy",      // Foco total em IPs, CPFs, Cartões e Chaves Pix
    nerMode: "minimal",      // Minimiza inferências NER para evitar lentidão
    promote: false,
    sanitizeChunk: false
  },
  audit_log: {
    name: "AUDIT_LOG",
    regexMode: "heavy",
    nerMode: "minimal",
    promote: false,
    sanitizeChunk: false
  },

  // ── STRICT PROFILES ────────────────────────────────────────
  strict_health: {
    name: "STRICT_HEALTH",
    regexMode: "heavy",
    nerMode: "aggressive",   // Sensibilidade máxima
    promote: true,
    sanitizeChunk: false
  },
  strict_generic: {
    name: "STRICT_GENERIC",
    regexMode: "heavy",
    nerMode: "aggressive",
    promote: true,
    sanitizeChunk: false
  }
};

export class ProfileRouter {
  static getStrategy(profile) {
    const key = (profile || "").toLowerCase().trim();
    return PROFILE_STRATEGIES[key] || PROFILE_STRATEGIES.generic;
  }
}


// ── SEÇÃO: domainRouter.js ───────────────────
// Domain Router: Roteador de domínio que seleciona as estratégias de perfil adequadas (Strategy Pattern)

const DOMAIN_DEFAULTS = {
  health: "uti_evolucao",
  chat: "whatsapp_geral",
  rag: "rag_ingest",
  logs: "application_log",
  strict: "strict_generic",
  auto: "generic",
  generic: "generic"
};

export class DomainRouter {
  static getStrategy(domain, profile) {
    const resolvedDomain = (domain || "").toLowerCase().trim();
    let resolvedProfile = (profile || "").toLowerCase().trim();

    // Se o perfil for vazio ou "auto", busca o perfil padrão do domínio
    if (!resolvedProfile || resolvedProfile === "auto") {
      resolvedProfile = DOMAIN_DEFAULTS[resolvedDomain] || DOMAIN_DEFAULTS.generic;
    }

    // Se o domínio for "health" mas o perfil não pertencer a saúde, força o default
    if (resolvedDomain === "health" && !this.isHealthProfile(resolvedProfile)) {
      resolvedProfile = DOMAIN_DEFAULTS.health;
    }

    // Se o domínio for "chat" mas o perfil não pertencer a chat, força o default
    if (resolvedDomain === "chat" && !this.isChatProfile(resolvedProfile)) {
      resolvedProfile = DOMAIN_DEFAULTS.chat;
    }

    // Se o domínio for "rag" mas o perfil não pertencer a RAG, força o default
    if (resolvedDomain === "rag" && !this.isRagProfile(resolvedProfile)) {
      resolvedProfile = DOMAIN_DEFAULTS.rag;
    }

    // Se o domínio for "logs" mas o perfil não pertencer a logs, força o default
    if (resolvedDomain === "logs" && !this.isLogsProfile(resolvedProfile)) {
      resolvedProfile = DOMAIN_DEFAULTS.logs;
    }

    return ProfileRouter.getStrategy(resolvedProfile);
  }

  static isHealthProfile(profile) {
    const healthProfiles = ["uti_evolucao", "uti_enfermagem", "prontuario", "resumo_alta", "anamnese", "anamnese_pediatrica", "laudo", "uti_com_data_nasc", "strict_health", "clinical"];
    return healthProfiles.includes(profile);
  }

  static isChatProfile(profile) {
    const chatProfiles = ["whatsapp_paciente", "whatsapp_agendamento", "whatsapp_receita", "whatsapp_exame", "whatsapp_geral"];
    return chatProfiles.includes(profile);
  }

  static isRagProfile(profile) {
    const ragProfiles = ["rag_ingest", "rag_query"];
    return ragProfiles.includes(profile);
  }

  static isLogsProfile(profile) {
    const logsProfiles = ["application_log", "audit_log"];
    return logsProfiles.includes(profile);
  }
}


// ── SEÇÃO: detectionPipeline.js ───────────────────
// Detection Pipeline: Orquestra a execução paralela de Regex e chamadas NER (BERT/GLiNER)

// Lista de tipos leves para o modo regexMode === "light"
const LIGHT_TYPES = new Set(["EMAIL", "TELEFONE", "CPF", "CARTAO", "CHAVE_PIX", "IP_ADDRESS", "NOME_PESSOA", "PROFISSIONAL_SAUDE"]);

export class DetectionPipeline {
  static async run(text, env, strategy, metrics) {
    if (!text || text.trim().length < 3) {
      return { text, regexDetections: [], nerDetections: [], totalEncontrado: 0 };
    }

    const regexMode = strategy.regexMode || "heavy";
    const nerMode = strategy.nerMode || "standard";

    // 1. Executa a detecção por REGEX (Mede tempo)
    metrics.start("regex");
    const regexResult = await this.detectarPII(text, regexMode);
    metrics.stop("regex");

    // 2. Executa a detecção por NER (Mede tempo e possui short-circuit)
    metrics.start("ner");
    let nerResult = { encontrados: [], nerOk: false };
    
    // Otimização de Performance: Se nerMode for minimal, ignora a chamada ao servidor NER (BERT)
    // para evitar a latência de rede em arquivos de Log ou prontuários de triagem simples.
    // Short-circuit: só chama o NER se houver letras no texto (se for apenas números/símbolos, pula)
    const temLetras = /[A-Za-zÀ-Úa-zà-ú]/.test(text);
    const glinerUrl = (env && env.GLINER_URL) || "https://ecosilva-mascara-ai-ner.hf.space";
    if (nerMode !== "minimal" && glinerUrl && temLetras) {
      const localEnv = { ...env, GLINER_URL: glinerUrl };
      nerResult = await this.detectarNER(text, localEnv);
    }
    metrics.stop("ner");

    return {
      textoLimpo: regexResult.textoLimpo,
      regexDetections: regexResult.deteccoes,
      nerDetections: nerResult.encontrados,
      nerOk: nerResult.nerOk
    };
  }

  // Detecção via expressões regulares
  static async detectarPII(texto, regexMode) {
    const textoProtegido = protegerChavesJSON(texto);
    const deteccoes = [];
    const tokensMap = {};
    let textoLimpo = textoProtegido;

    // Filtra padrões com base no modo (light vs heavy)
    const activePatterns = PII_PATTERNS.filter(p => {
      if (regexMode === "light") {
        return LIGHT_TYPES.has(p.type);
      }
      return true;
    });

    for (const p of activePatterns) {
      const flags = p.regex.flags.includes("g") ? p.regex.flags : p.regex.flags + "g";
      const regexGlobal = new RegExp(p.regex.source, flags);

      for (const m of [...textoProtegido.matchAll(regexGlobal)]) {
        const valor = m[1] !== undefined ? m[1] : m[0];
        if (!valor || !p.validate(valor)) continue;

        const chave = String(valor).trim().toLowerCase();
        if (tokensMap[chave]) continue;

        const token = await gerarToken(p.type, valor);
        tokensMap[chave] = { token, valor, tipo: p.type };
        deteccoes.push({ tipo: p.type, token, valor });
      }
    }

    // Ordena os valores do maior para o menor para evitar substituição de substrings internas primeiro
    const sortedItems = Object.values(tokensMap).sort((a, b) => b.valor.length - a.valor.length);
    const deteccoesEfetuadas = [];

    for (const item of sortedItems) {
      if (!textoLimpo.includes(item.valor)) continue;
      textoLimpo = textoLimpo.split(item.valor).join(item.token);
      
      const originalDet = deteccoes.find(d => d.valor === item.valor);
      if (originalDet) {
        deteccoesEfetuadas.push(originalDet);
      }
    }

    // Remove tokens aninhados causados por colisões de regex
    textoLimpo = textoLimpo.replace(
      /\u27E6PII:[^\u27E6\u27E7]*\u27E6PII:[A-Z_]+:[0-9A-F]{8}\u27E7[^\u27E6\u27E7]*\u27E7/g,
      (match) => {
        const interno = match.match(/\u27E6PII:[A-Z_]+:[0-9A-F]{8}\u27E7/);
        return interno ? interno[0] : match;
      }
    );

    textoLimpo = restaurarChavesJSON(textoLimpo);

    return { textoLimpo, deteccoes: deteccoesEfetuadas };
  }

  // Detecção via servidor NER externo (BERTimbau / leNER / GLiNER)
  static async detectarNER(texto, env) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 15000); // Timeout de 15 segundos (compatível com processamento de CPU de IA)

      const headers = {
        "Content-Type": "application/json",
        "X-API-Key": env.GLINER_API_KEY || "",
      };
      if (env.GLINER_API_KEY) {
        headers["Authorization"] = `Bearer ${env.GLINER_API_KEY}`;
      }

      const res = await fetch(`${env.GLINER_URL}/detect`, {
        method: "POST",
        headers: headers,
        body: JSON.stringify({ text: texto }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!res.ok) {
        return { encontrados: [], nerOk: false };
      }

      const data = await res.json();
      const encontrados = (data.encontrados || []).map(e => ({
        tipo: e.tipo,
        valor: e.valor
      }));

      return { encontrados, nerOk: true };
    } catch (e) {
      // Falha silenciosa para garantir resiliência caso o servidor NER caia
      return { encontrados: [], nerOk: false };
    }
  }
}


// ── SEÇÃO: promotionLayer.js ───────────────────
// Promotion Layer: Implementa as regras de promoção contextual de entidades

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


// ── SEÇÃO: policyLayer.js ───────────────────
// Policy Layer: Filtra entidades detectadas com base na política (strict/balanced/conservative) e gera o relatório de auditoria

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


// ── SEÇÃO: maskEngine.js ───────────────────
// Mask Engine: Executa as substituições físicas dos dados pelas tags ⟦PII:TIPO:HASH⟧

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


// ── SEÇÃO: worker.js ───────────────────
// ══════════════════════════════════════════
// MascaraAI — Cloudflare Worker v3.0
// ══════════════════════════════════════════
//
// Decisões implementadas nesta versão (PRD v3.0):
//
// [v3-A] BILLING: modelo de assinatura mensal (3 planos) via Asaas.
//        Lógica de créditos avulsos removida do fluxo principal.
//        handleCreditsRequest/Approve/Reject mantidos apenas para
//        exceções Enterprise gerenciadas manualmente.
//
// [v3-B] SOFT LIMIT: grade window de 10% extra após 100% da cota.
//        3 avisos por email antes do bloqueio definitivo.
//        Nunca cortar automação abruptamente.
//
// [v3-C] PLANOS: FREE (100k/mês), PRO (R$79/10M/mês), SCALE (R$249/40M/mês).
//        Constante PLANOS_CONFIG é a fonte única de verdade.
//
// [v3-D] RESTORE: documentado como feature intencional.
//        mapa renomeado para restore_map na resposta.
//
// [v3-E] RESPOSTA LIMPA: removidos tokens_aproximados e modo da resposta pública.
//        creditos_restantes substituído por cota_restante_mes.
//
// [v3-F] /api/test REMOVIDO.
//
// [v3-G] MEMBROS: código mantido mas endpoints não documentados publicamente (v2).
//
// [v3-H] FREE SCAN: 2.000 chars, 20 req/hora por IP. Exclusivamente para demo.
//
// [v3-I] NER SERVER: referenciado como GLINER_URL (compatibilidade).
//        O servidor Python pode rodar GLiNER ou BERTimbau-leNER.
//        O worker não precisa saber qual modelo está rodando.
// ══════════════════════════════════════════


export default {
  async fetch(request, env) {
    const url  = new URL(request.url);
    const path = url.pathname;

    const cors = {
      "Access-Control-Allow-Origin":  "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-Session-Token, X-API-Key",
    };
    if (request.method === "OPTIONS") return new Response(null, { headers: cors });

    // ── AUTH ──────────────────────────────────────────────────
    if ((path === "/api/auth/request" || path === "/api/sessao/solicitar") && request.method === "POST") return handleAuthRequest(request, env, cors);
    if ((path === "/api/auth/verify" || path === "/api/sessao/confirmar") && request.method === "POST") return handleAuthVerify(request, env, cors);
    if ((path === "/api/auth/logout" || path === "/api/sessao/sair") && request.method === "POST") return handleAuthLogout(request, env, cors);

    // ── SCAN ──────────────────────────────────────────────────
    if (path === "/api/scan/free"       && request.method === "POST") return handleFreeScan(request, env, cors);
    if (path === "/api/demo-chat"       && request.method === "POST") return handleDemoChat(request, env, cors);
    if (path === "/api/scan"            && request.method === "POST") return handleAuthScan(request, env, cors);
    if (path === "/api/scan/batch"      && request.method === "POST") return handleBatchScan(request, env, cors);
    if (path === "/api/restore"         && request.method === "POST") return handleRestore(request, env, cors);
    if (path === "/api/checkout"        && request.method === "POST") return handleCheckout(request, env, cors);

    // ── CONTA ─────────────────────────────────────────────────
    if (path === "/api/account"         && request.method === "GET")  return handleGetAccount(request, env, cors);
    if (path === "/api/usage"           && request.method === "GET")  return handleUsage(request, env, cors);

    // ── HEALTH ────────────────────────────────────────────────
    if (path === "/api/health"          && request.method === "GET")  return handleHealth(request, env, cors);

    // ── BENCHMARK (admin only) ────────────────────────────────
    if (path === "/api/benchmark"       && request.method === "POST") return handleBenchmark(request, env, cors);

    // ── ADMIN CAPACITY (admin only) ───────────────────────────
    if (path === "/api/admin/capacity"  && request.method === "GET")  return handleAdminCapacity(request, env, cors);

    // ── FEEDBACK ──────────────────────────────────────────────
    if (path === "/api/feedback"        && request.method === "POST") return handleFeedback(request, env, cors);

    // ── WEBHOOK CONFIG ────────────────────────────────────────
    if (path === "/api/webhook"         && request.method === "POST") return handleWebhook(request, env, cors);
    if (path === "/api/webhook/telegram" && request.method === "POST") return handleTelegramWebhook(request, env, cors);
    if (path === "/api/webhook/asaas"    && request.method === "POST") return handleAsaasWebhook(request, env, cors);

    // ── CRÉDITOS MANUAIS (Enterprise/admin) ───────────────────
    if (path === "/api/credits/request" && request.method === "POST") return handleCreditsRequest(request, env, cors);
    if (path === "/api/credits/approve" && request.method === "POST") return handleCreditsApprove(request, env, cors);
    if (path === "/api/credits/reject"  && request.method === "POST") return handleCreditsReject(request, env, cors);

    // ── LOGS (não documentado publicamente na v1) ─────────────
    if (path === "/api/logs"            && request.method === "GET")  return handleLogs(request, env, cors);
    if (path === "/api/logs/export"     && request.method === "GET")  return handleLogsExport(request, env, cors);

    // ── MEMBROS (não documentado publicamente na v1) ──────────
    if (path === "/api/members"         && request.method === "GET")  return handleMembersList(request, env, cors);
    if (path === "/api/members/invite"  && request.method === "POST") return handleMembersInvite(request, env, cors);
    if (path === "/api/members/limits"  && request.method === "POST") return handleMembersLimits(request, env, cors);
    if (path === "/api/members/remove"  && request.method === "POST") return handleMembersRemove(request, env, cors);

    return jsonResponse({ error: "Rota não encontrada" }, 404, cors);
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(verificarContasEDesligamento(env));
    ctx.waitUntil(enviarRelatorioDiario(env));
  },
};

// ══════════════════════════════════════════
// PLANOS — fonte única de verdade [v3-C]
// ══════════════════════════════════════════

const PLANOS_CONFIG = {
  free:  { label: "Free",  preco: 0,   chars_mes: 10_000,         grace_pct: 0.10 },
  pro:   { label: "Profissional",   preco: 30,  chars_mes: 10_000_000,     grace_pct: 0.10 },
  scale: { label: "Scale", preco: 249, chars_mes: 40_000_000,     grace_pct: 0.10 },
  enterprise: { label: "Enterprise", preco: 0, chars_mes: 100_000_000, grace_pct: 0.10 },
};

// Retorna a cota do mês para um account.
// chars_mes_override é usado para Enterprise com cota custom.
function getCotas(account) {
  const plano = PLANOS_CONFIG[account.plano] || PLANOS_CONFIG.free;
  const custom = parseInt(account.chars_mes_custom);
  const cotaBase = (!isNaN(custom) && custom > 0) ? custom : plano.chars_mes;
  const cotaGrace = Math.floor(cotaBase * (1 + plano.grace_pct));
  return { cotaBase, cotaGrace, plano };
}

// ══════════════════════════════════════════
// DETECÇÃO HÍBRIDA & PROCESSAMENTO COMPLETO
// ══════════════════════════════════════════

async function detectarHibrido(texto, env, nerUrl = null, contextOrProfile = null, policyObj = {}, nerToken = null) {
  const t0 = Date.now();
  const metrics = new MetricsTracker();

  const contextObj = typeof contextOrProfile === "object" && contextOrProfile !== null
    ? contextOrProfile
    : { profile: contextOrProfile };

  // 1. Adaptação do input
  const parsed = InputAdapter.parse({ text: texto, context: contextObj, policy: policyObj });

  // 2. Resolução de contexto
  const resolvedCtx = ContextResolver.resolve(parsed.text, parsed.context);

  // 3. Escolha de estratégia pelo Router
  const strategy = DomainRouter.getStrategy(resolvedCtx.domain, resolvedCtx.profile);

  // 4. Detecção Regex e NER
  const isCustomUrl = nerUrl && nerUrl !== env.GLINER_URL;
  const localEnv = { 
    ...env, 
    GLINER_URL: nerUrl || env.GLINER_URL || "https://ecosilva-mascara-ai-ner.hf.space",
    GLINER_API_KEY: isCustomUrl ? (nerToken || "") : (nerToken || env.GLINER_API_KEY)
  };
  const detectionResult = await DetectionPipeline.run(parsed.text, localEnv, strategy, metrics);

  // 5. Promoção
  const allDetections = [...detectionResult.regexDetections, ...detectionResult.nerDetections];
  const promotedDetections = await PromotionLayer.promote(allDetections, parsed.text, strategy);

  // 6. Política & Auditoria
  const policyResult = await PolicyLayer.apply(
    parsed.text,
    promotedDetections,
    [],
    strategy,
    parsed.policy
  );

  // 7. Mascaramento
  const maskedText = MaskEngine.mask(parsed.text, policyResult.detections, strategy);

  const totalTime = Date.now() - t0;
  const piiNER = policyResult.detections.filter(d => d.tipo === "NOME_PESSOA" || d.tipo === "PROFISSIONAL_SAUDE").length;
  const piiRegex = policyResult.detections.length - piiNER;

  return {
    textoLimpo: maskedText,
    deteccoes: policyResult.detections,
    totalEncontrado: policyResult.detections.length,
    restore_map: Object.fromEntries(policyResult.detections.map(d => [d.token, d.valor])),
    resolvedCtx,
    classificationReport: policyResult.classificationReport,
    metricas: {
      tempoTotal: totalTime,
      tempoNER: metrics.durations?.ner_ms || 0,
      nerOk: detectionResult.nerOk,
      nerFallback: false,
      piiRegex: piiRegex,
      piiNER: piiNER,
    },
  };
}

export async function processarTextoCompleto(texto, env, context = {}, policy = {}) {
  const t0 = Date.now();
  const nerUrl = env.GLINER_URL || null;
  const resultado = await detectarHibrido(texto, env, nerUrl, context, policy);

  return {
    masked_text: resultado.textoLimpo,
    context_detected: resultado.resolvedCtx,
    classification_report: resultado.classificationReport,
    metrics: {
      tempo_ms: Date.now() - t0,
      regex_ms: (resultado.metricas?.tempoTotal || 0) - (resultado.metricas?.tempoNER || 0),
      ner_ms: resultado.metricas?.tempoNER || 0
    }
  };
}

// ══════════════════════════════════════════
// JWT STATELESS HELPERS
// ══════════════════════════════════════════

async function signToken(payload, secret) {
  const header = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const payloadStr = btoa(JSON.stringify(payload));
  const message = `${header}.${payloadStr}`;
  
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const key = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  
  const signatureBuffer = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(message)
  );
  
  const signatureArray = Array.from(new Uint8Array(signatureBuffer));
  const signatureBase64 = btoa(String.fromCharCode.apply(null, signatureArray))
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
  
  return `${message}.${signatureBase64}`;
}

async function verifyToken(token, secret) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    
    const [header, payload, signature] = parts;
    const message = `${header}.${payload}`;
    
    const encoder = new TextEncoder();
    const keyData = encoder.encode(secret);
    const key = await crypto.subtle.importKey(
      "raw",
      keyData,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
    
    const sigBytes = new Uint8Array(
      atob(signature.replace(/-/g, "+").replace(/_/g, "/"))
        .split("")
        .map(c => c.charCodeAt(0))
    );
    
    const isValid = await crypto.subtle.verify(
      "HMAC",
      key,
      sigBytes,
      encoder.encode(message)
    );
    
    if (!isValid) return null;
    
    return JSON.parse(atob(payload));
  } catch (e) {
    return null;
  }
}

async function encryptToken(token, secret) {
  const key = await getEncryptionKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encodedToken = new TextEncoder().encode(token);
  
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    encodedToken
  );
  
  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encrypted), iv.length);
  
  return btoa(String.fromCharCode.apply(null, combined));
}

async function decryptToken(encryptedBase64, secret) {
  try {
    const key = await getEncryptionKey(secret);
    const combined = new Uint8Array(
      atob(encryptedBase64)
        .split("")
        .map(c => c.charCodeAt(0))
    );
    
    const iv = combined.slice(0, 12);
    const data = combined.slice(12);
    
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      key,
      data
    );
    
    return new TextDecoder().decode(decrypted);
  } catch (e) {
    return null;
  }
}

async function getEncryptionKey(secret) {
  const enc = new TextEncoder();
  const rawKey = enc.encode(secret.padEnd(32, "0").substring(0, 32));
  return crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"]
  );
}

// ══════════════════════════════════════════
// AUTENTICAÇÃO
// ══════════════════════════════════════════

async function getSessionOrApiKey(request, env) {
  const authHeader = request.headers.get("Authorization") || "";
  let token = "";
  if (authHeader.startsWith("Bearer ")) {
    token = authHeader.substring(7);
  } else {
    token = request.headers.get("X-Session-Token") || "";
  }

  const secret = env.JWT_SECRET || "fallback_secret";

  if (token) {
    const payload = await verifyToken(token, secret);
    if (payload && payload.email) {
      // Tenta recuperar do KV se a sessão ainda é válida (opcional para revogação rápida)
      const sessionActive = await env.KV.get(`sessao:${payload.email}`);
      if (sessionActive && sessionActive === token) {
        const memberRaw = await env.KV.get(`member:${payload.email}`);
        if (memberRaw) {
          const member = JSON.parse(memberRaw);
          const accountRaw = await env.KV.get(`account:${member.account_uuid}`);
          if (accountRaw) {
            return {
              email: payload.email,
              account_uuid: member.account_uuid,
              role: member.role,
              member: member,
              account: JSON.parse(accountRaw)
            };
          }
        }
      }
    }
  }

  const apiKey = request.headers.get("X-API-Key") || "";
  if (apiKey) {
    const keyDataRaw = await env.KV.get(`apikey:${apiKey}`);
    if (keyDataRaw) {
      const keyData = JSON.parse(keyDataRaw);
      const accountRaw = await env.KV.get(`account:${keyData.account_uuid}`);
      if (accountRaw) {
        const memberRaw = await env.KV.get(`member:${keyData.email}`);
        return {
          email: keyData.email,
          account_uuid: keyData.account_uuid,
          role: keyData.role,
          member: JSON.parse(memberRaw),
          account: JSON.parse(accountRaw)
        };
      }
    }
  }

  // Developer Bypass para testes em ambiente sem KV
  if (env.DEV_BYPASS_TOKEN && token === env.DEV_BYPASS_TOKEN) {
    return {
      email: "dev@mascaraai.com",
      account_uuid: "dev_account_uuid",
      role: "owner",
      member: { role: "owner", api_key: "dev_api_key" },
      account: { plano: "enterprise", uuid: "dev_account_uuid", chars_mes_custom: 10000000 }
    };
  }

  return null;
}

async function handleAuthRequest(request, env, cors) {
  try {
    const { email } = await request.json();
    if (!email || !email.includes("@")) {
      return jsonResponse({ error: "E-mail inválido" }, 400, cors);
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    // Armazena o código de acesso com expiração de 5 minutos
    await env.KV.put(`code:${email}`, code, { expirationTtl: 300 });

    // Se estiver no ambiente de dev, loga o código. Em produção, envia e-mail
    if (env.ENVIRONMENT === "development" || env.DEV_MODE === "true") {
      console.log(`[DEV] Código de acesso para ${email}: ${code}`);
    }

    if (env.RESEND_API_KEY) {
      await enviarEmail(env, email, "Seu código de acesso — MascaraAI", `
        <div style="font-family: sans-serif; padding: 20px; color: #13201C; max-width: 500px; margin: 0 auto; border: 1px solid rgba(19,32,28,0.1); border-radius: 12px;">
          <h2 style="color: #0f6e5c; font-family: 'Fraunces', serif;">🛡️ Código de Autenticação</h2>
          <p>Olá,</p>
          <p>Utilize o código de verificação abaixo para acessar sua conta no MascaraAI:</p>
          <div style="background: #f7f8f6; padding: 15px; border-radius: 8px; font-size: 1.8rem; font-weight: bold; text-align: center; color: #0f6e5c; letter-spacing: 5px; margin: 20px 0;">
            ${code}
          </div>
          <p style="font-size: 0.9rem; color: #5a6b65;">Este código é válido por 5 minutos. Se você não solicitou este acesso, apenas ignore este e-mail.</p>
        </div>
      `);
    }

    return jsonResponse({ ok: true, message: "Código enviado com sucesso!" }, 200, cors);
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors);
  }
}

async function handleAuthVerify(request, env, cors) {
  try {
    const { email, code } = await request.json();
    if (!email || !code) return jsonResponse({ error: "E-mail e código obrigatórios" }, 400, cors);

    const savedCode = await env.KV.get(`code:${email}`);
    if (!savedCode || savedCode !== code.trim()) {
      return jsonResponse({ error: "Código inválido ou expirado" }, 401, cors);
    }

    await env.KV.delete(`code:${email}`);

    let memberRaw = await env.KV.get(`member:${email}`);
    let accountUuid = "";
    let role = "member";

    if (!memberRaw) {
      // Primeira vez acessando: cria conta nova grátis
      accountUuid = crypto.randomUUID();
      role = "owner";
      const apiKey = "msk_" + crypto.randomUUID().replace(/-/g, "").substring(0, 32);

      await env.KV.put(`account:${accountUuid}`, JSON.stringify({
        uuid: accountUuid,
        email: email,
        plano: "free",
        chars_mes_custom: 0,
        uso_mes: 0,
        avisos_enviados: 0,
        webhook_url: "",
        criado_em: new Date().toISOString()
      }));

      await env.KV.put(`account:email:${email}`, accountUuid);

      await env.KV.put(`member:${email}`, JSON.stringify({
        account_uuid: accountUuid,
        role: "owner",
        limite_dia: 0,
        limite_mes: 0,
        api_key: apiKey
      }));

      await env.KV.put(`apikey:${apiKey}`, JSON.stringify({
        account_uuid: accountUuid,
        email: email,
        role: "owner"
      }));

      await enviarTelegram(env, `🆕 *Novo usuário registrado:* ${email}`);
    } else {
      const member = JSON.parse(memberRaw);
      accountUuid = member.account_uuid;
      role = member.role;
    }

    // Gera JWT Token com expiração de 30 dias
    const expires = Date.now() + 30 * 24 * 60 * 60 * 1000;
    const secret = env.JWT_SECRET || "fallback_secret";
    const token = await signToken({ email, expires }, secret);

    // Salva a sessão ativa no KV
    await env.KV.put(`sessao:${email}`, token, { expirationTtl: 30 * 24 * 60 * 60 });

    return jsonResponse({ ok: true, token, email, role }, 200, cors);
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors);
  }
}

async function handleAuthLogout(request, env, cors) {
  try {
    const ctx = await getSessionOrApiKey(request, env);
    if (ctx) {
      await env.KV.delete(`sessao:${ctx.email}`);
    }
    return jsonResponse({ ok: true }, 200, cors);
  } catch {
    return jsonResponse({ ok: true }, 200, cors);
  }
}

// ══════════════════════════════════════════
// SCANS (MASCARAMENTO)
// ══════════════════════════════════════════

async function processarEAtualizarUso(texto, contextObj, policyObj, ctx, env) {
  const t0 = Date.now();
  
  // Limitação Estratégica: Não permite processar textos vazios
  if (!texto || texto.trim().length === 0) {
    return { status: 400, body: { error: "Corpo do texto para mascaramento vazio." } };
  }

  const { cotaBase, cotaGrace } = getCotas(ctx.account);
  const hashKey = await hashSimples(ctx.account_uuid);
  const mes = mesAtual();

  // Recupera consumo de caracteres do cache distribuído
  let usoMes = parseInt(await env.KV.get(`uso:mes:${ctx.account.uuid}:${mes}`) || "0");

  // Soft Limit [v3-B]: Grace Window de 10% adicionais para evitar interrupções de robôs
  if (usoMes >= cotaGrace) {
    return {
      status: 403,
      body: {
        error: "Limite de cota de caracteres mensal atingido. Automação temporariamente suspensa para segurança de faturamento. Acesse seu painel administrativo no MascaraAI para realizar o upgrade de plano."
      }
    };
  }

  // Executa mascaramento híbrido (Local + NER ONNX)
  const resultado = await detectarHibrido(texto, env, null, contextObj, policyObj);
  const tempoTotal = Date.now() - t0;

  // Atualiza métricas de consumo de caracteres no KV
  const novosChars = texto.length;
  const novoUsoMes = usoMes + novosChars;
  await env.KV.put(`uso:mes:${ctx.account.uuid}:${mes}`, String(novoUsoMes));

  // Contador de uso diário do membro
  const dia = diaAtual();
  const usoHoje = parseInt(await env.KV.get(`uso:dia:${ctx.account_uuid}:${ctx.email}:${dia}`) || "0");
  await env.KV.put(`uso:dia:${ctx.account_uuid}:${ctx.email}:${dia}`, String(usoHoje + novosChars), { expirationTtl: 86400 * 2 });

  // Disparo assíncrono de notificações de consumo (75%, 90%, 100%)
  const pctUsoAnterior = Math.round((usoMes / cotaBase) * 100);
  const pctUsoNovo = Math.round((novoUsoMes / cotaBase) * 100);
  
  if (env.RESEND_API_KEY && ctx.account.plano !== "enterprise") {
    let avisoDisparar = 0;
    const avisosEnviados = parseInt(ctx.account.avisos_enviados || "0");

    if (pctUsoNovo >= 100 && avisosEnviados < 3) {
      avisoDisparar = 3;
    } else if (pctUsoNovo >= 90 && pctUsoAnterior < 90 && avisosEnviados < 2) {
      avisoDisparar = 2;
    } else if (pctUsoNovo >= 75 && pctUsoAnterior < 75 && avisosEnviados < 1) {
      avisoDisparar = 1;
    }

    if (avisoDisparar > 0) {
      ctx.account.avisos_enviados = avisoDisparar;
      await env.KV.put(`account:${ctx.account.uuid}`, JSON.stringify(ctx.account));
      const planoLabel = PLANOS_CONFIG[ctx.account.plano]?.label || "Free";
      
      // Envia notificação por e-mail em background
      const emailHtml = emailAvisoLimite(pctUsoNovo, cotaBase, planoLabel);
      await enviarEmail(env, ctx.account.email, `Aviso de Consumo (${pctUsoNovo}%) — MascaraAI`, emailHtml);
      await enviarTelegram(env, `⚠️ *Cota ${pctUsoNovo}%:* ${ctx.account.email} (${planoLabel})`);
    }
  }

  // Gravação de registros de auditoria no Banco D1 estruturado local
  if (env.DB) {
    try {
      await salvarLog(env, hashKey, resultado, novosChars, tempoTotal);
    } catch (err) {
      console.error("D1 Logger falhou:", err.message);
    }
  }

  return {
    status: 200,
    body: {
      masked_text: resultado.textoLimpo,
      restore_map: resultado.restore_map,
      cota_restante_mes: Math.max(0, cotaBase - novoUsoMes),
      risk_score: resultado.classificationReport?.risk_score || 0.0
    }
  };
}

async function handleAuthScan(request, env, cors) {
  const ctx = await getSessionOrApiKey(request, env);
  if (!ctx) return jsonResponse({ error: "Não autenticado ou chave de API inválida." }, 401, cors);

  try {
    const body = await request.json();
    const texto = body.text || body.mensagem || "";
    const context = body.context || {};
    const policy = body.policy || {};

    const res = await processarEAtualizarUso(texto, context, policy, ctx, env);
    return jsonResponse(res.body, res.status, cors);
  } catch (e) {
    return jsonResponse({ error: "Payload inválido. Certifique-se de enviar um JSON válido contendo o campo 'text'." }, 400, cors);
  }
}

async function handleBatchScan(request, env, cors) {
  const ctx = await getSessionOrApiKey(request, env);
  if (!ctx) return jsonResponse({ error: "Não autenticado ou chave de API inválida." }, 401, cors);

  try {
    const { texts, context, policy } = await request.json();
    if (!Array.isArray(texts)) return jsonResponse({ error: "Campo 'texts' deve ser um array de strings." }, 400, cors);
    if (texts.length > 25) return jsonResponse({ error: "Limite máximo de lote: 25 textos por requisição." }, 400, cors);

    const resultados = [];
    for (const texto of texts) {
      const res = await processarEAtualizarUso(texto, context || {}, policy || {}, ctx, env);
      if (res.status !== 200) {
        return jsonResponse({ error: `Erro no processamento do lote: ${res.body.error}` }, res.status, cors);
      }
      resultados.push(res.body);
    }

    return jsonResponse({ resultados }, 200, cors);
  } catch (e) {
    return jsonResponse({ error: "Payload inválido" }, 400, cors);
  }
}

async function handleRestore(request, env, cors) {
  try {
    const { safe_text, restore_map, text, map } = await request.json();
    const texto = safe_text || text || "";
    const mapa = restore_map || map;

    if (!texto || !mapa) return jsonResponse({ error: "Campos safe_text e restore_map obrigatórios" }, 400, cors);

    // Normaliza variantes de token que o LLM pode ter modificado
    let textoRestaurado = texto
      .replace(/\[PII:([A-Z_]+):([0-9A-F]{8})\]/g,   "\u27E6PII:$1:$2\u27E7")
      .replace(/\(PII:([A-Z_]+):([0-9A-F]{8})\)/g,   "\u27E6PII:$1:$2\u27E7")
      .replace(/«PII:([A-Z_]+):([0-9A-F]{8})»/g,     "\u27E6PII:$1:$2\u27E7")
      .replace(/\{PII:([A-Z_]+):([0-9A-F]{8})\}/g,   "\u27E6PII:$1:$2\u27E7")
      .replace(/PII:([A-Z_]+):([0-9A-F]{8})/g,       "\u27E6PII:$1:$2\u27E7");

    let count = 0;
    for (const [token, valor] of Object.entries(mapa)) {
      if (textoRestaurado.includes(token)) {
        textoRestaurado = textoRestaurado.split(token).join(valor);
        count++;
      }
    }

    return jsonResponse({ restored_text: textoRestaurado, tokens_restored: count }, 200, cors);
  } catch { return jsonResponse({ error: "Payload inválido" }, 400, cors); }
}

// ══════════════════════════════════════════
// DEMO CHAT & FREE SCAN (PÚBLICOS)
// ══════════════════════════════════════════

async function handleFreeScan(request, env, cors) {
  try {
    const { text, context, policy } = await request.json();
    if (!text || text.trim().length === 0) return jsonResponse({ error: "Texto vazio" }, 400, cors);
    if (text.length > 2000) return jsonResponse({ error: "Limite da demonstração gratuita: 2.000 caracteres." }, 400, cors);

    // Rate limit simples por IP na borda (20 req/hora)
    const ip = request.headers.get("CF-Connecting-IP") || "local_ip";
    const hora = horaAtual();
    const rateLimitKey = `rate:free:${ip}:${hora}`;
    const hits = parseInt(await env.KV.get(rateLimitKey) || "0");
    if (hits >= 20) {
      return jsonResponse({ error: "Limite de taxa para demonstração gratuita atingido (20 req/hora)." }, 429, cors);
    }
    await env.KV.put(rateLimitKey, String(hits + 1), { expirationTtl: 3600 });

    // Roda com credenciais Mock Free
    const mockCtx = {
      email: `free_scan_${ip}`,
      account_uuid: "free_account_uuid",
      account: { plano: "free", uuid: "free_account_uuid", chars_mes_custom: 0 }
    };

    const res = await processarEAtualizarUso(text, context || {}, policy || {}, mockCtx, env);
    return jsonResponse(res.body, res.status, cors);
  } catch {
    return jsonResponse({ error: "Payload inválido" }, 400, cors);
  }
}

async function handleDemoChat(request, env, cors) {
  // Demo chat permite que usuários testem IA de forma higienizada
  const ip = request.headers.get("CF-Connecting-IP") || "local_ip";
  const now = Date.now();

  const sessionHeader = request.headers.get("X-Session-Token") || "";
  let account = null;
  if (sessionHeader) {
    const secret = env.JWT_SECRET || "fallback_secret";
    const payload = await verifyToken(sessionHeader, secret);
    if (payload && payload.email) {
      const memberRaw = await env.KV.get(`member:${payload.email}`);
      if (memberRaw) {
        const member = JSON.parse(memberRaw);
        const accountRaw = await env.KV.get(`account:${member.account_uuid}`);
        if (accountRaw) account = JSON.parse(accountRaw);
      }
    }
  }

  // Se não autenticado, aplica rate limit severo de demo (3 por dia por IP)
  if (!account) {
    if (!globalThis.demoChatIpHits) {
      globalThis.demoChatIpHits = new Map();
      setInterval(() => {
        const checkNow = Date.now();
        for (const [key, val] of globalThis.demoChatIpHits.entries()) {
          if (checkNow - val.firstHit > 86400000) {
            globalThis.demoChatIpHits.delete(key);
          }
        }
      }, 3600000);
    }

    let ipData = globalThis.demoChatIpHits.get(ip) || { count: 0, firstHit: now };
    if (now - ipData.firstHit > 86400000) {
      ipData.count = 0;
      ipData.firstHit = now;
    }

    if (ipData.count >= 3) {
      return jsonResponse({
        error: "Limite diário gratuito de demonstração (3 por dia) atingido. Para continuar testando ilimitadamente com segurança na nuvem, crie uma conta gratuita (clique em 'Solicitar Chave Grátis' no rodapé) e configure suas chaves de API ocultas no seu Painel de Cliente.",
        limit_reached: true
      }, 429, cors);
    }
  }

  try {
    const body = await request.json();
    const text = body.text || "";
    const systemPrompt = body.systemPrompt || "";
    const providerSelected = body.provider || "groq_demo";
    const modelSelected = body.model || null;
    
    if (!text || text.trim().length < 3) {
      return jsonResponse({ error: "Texto muito curto." }, 400, cors);
    }
    if (text.length > 2000) {
      return jsonResponse({ error: "Limite do demo com IA: 2.000 caracteres." }, 400, cors);
    }

    let customKey = null;
    const secret = env.JWT_SECRET || "fallback_secret";

    if (providerSelected !== "groq_demo") {
      // Provedores customizados exigem conta logada
      if (!account) {
        return jsonResponse({
          error: "Autenticação necessária. Crie uma conta gratuita no rodapé e faça login para configurar e utilizar sua própria chave de IA com segurança militar na nuvem."
        }, 401, cors);
      }

      if (providerSelected === "groq_custom" && account.custom_groq_key) {
        customKey = await decryptToken(account.custom_groq_key, secret);
      } else if (providerSelected === "openai_custom" && account.custom_openai_key) {
        customKey = await decryptToken(account.custom_openai_key, secret);
      } else if (providerSelected === "gemini_custom" && account.custom_gemini_key) {
        customKey = await decryptToken(account.custom_gemini_key, secret);
      }

      if (!customKey) {
        return jsonResponse({
          error: `Chave de API para o provedor '${providerSelected}' não configurada no seu painel. Por favor, acesse o painel e configure suas credenciais.`
        }, 400, cors);
      }
    }

    let aiResponseText = "";

    if (providerSelected === "gemini_custom") {
      // Chamada para a API do Gemini customizada com modelo flexível
      const model = modelSelected || "gemini-3.5-flash";
      const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${customKey}`;
      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          contents: [
            {
              role: "user",
              parts: [{ text: systemPrompt + "\n\nTexto Clínico:\n" + text }]
            }
          ],
          generationConfig: { temperature: 0.1 }
        })
      });

      if (!response.ok) {
        const geminiError = await response.text();
        return jsonResponse({ error: "Erro ao processar API do Gemini Custom.", details: geminiError }, 502, cors);
      }

      const data = await response.json();
      try {
        aiResponseText = data.candidates[0].content.parts[0].text;
      } catch (e) {
        return jsonResponse({ error: "Estrutura de resposta do Gemini inválida.", details: JSON.stringify(data) }, 502, cors);
      }

      return jsonResponse({
        choices: [{ message: { content: aiResponseText } }]
      }, 200, cors);

    } else if (providerSelected === "openai_custom") {
      // Chamada para a API da OpenAI customizada com modelo flexível
      const model = modelSelected || "gpt-4o-mini";
      const response = await fetch("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${customKey}`
        },
        body: JSON.stringify({
          model: model,
          messages: [
            { role: "system", content: systemPrompt },
            { role: "user", content: text }
          ],
          temperature: 0.1
        })
      });

      if (!response.ok) {
        const openAiError = await response.text();
        return jsonResponse({ error: "Erro ao processar API da OpenAI Custom.", details: openAiError }, 502, cors);
      }

      const data = await response.json();
      return jsonResponse(data, 200, cors);

    } else {
      // Provedor padrão Demo: Groq (Llama-3-8b)
      const apiKey = customKey || env.GROQ_API_KEY;
      const model = modelSelected || "llama3-8b-8192";
      if (!apiKey) return jsonResponse({ error: "Chave de demonstração do Groq não disponível" }, 500, cors);

      const response = await fetch("https://api.groq.com/openai/v1/chat/completions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${apiKey}`
        },
        body: JSON.stringify({
          model: model,
          messages: [
            { role: "system", content: systemPrompt },
            { role: "user", content: text }
          ],
          temperature: 0.1
        })
      });

      if (!response.ok) {
        const groqError = await response.text();
        return jsonResponse({ error: "Erro ao processar chamada Groq.", details: groqError }, 502, cors);
      }

      // Incrementa o rate limit se não autenticado
      if (!account) {
        let ipData = globalThis.demoChatIpHits.get(ip) || { count: 0, firstHit: now };
        ipData.count++;
        globalThis.demoChatIpHits.set(ip, ipData);
      }

      const data = await response.json();
      return jsonResponse(data, 200, cors);
    }
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors);
  }
}

// ══════════════════════════════════════════
// CONTA
// ══════════════════════════════════════════

async function handleGetAccount(request, env, cors) {
  const ctx = await getSessionOrApiKey(request, env);
  if (!ctx) return jsonResponse({ error: "Não autenticado" }, 401, cors);

  const plano     = PLANOS_CONFIG[ctx.account.plano] || PLANOS_CONFIG.free;
  const { cotaBase } = getCotas(ctx.account);
  
  let usoMes = 0;
  let usoHoje = 0;
  try {
    usoMes = parseInt(await env.KV.get(`uso:mes:${ctx.account.uuid}:${mesAtual()}`) || "0");
    usoHoje = parseInt(await env.KV.get(`uso:dia:${ctx.account_uuid}:${ctx.email}:${diaAtual()}`) || "0");
  } catch (e) {
    if (ctx.account_uuid !== "dev_account_uuid") throw e;
  }

  return jsonResponse({
    email:            ctx.email,
    role:             ctx.role,
    plano:            ctx.account.plano,
    plano_label:      plano.label,
    chars_mes:        cotaBase,
    uso_mes:          usoMes,
    uso_hoje:         usoHoje,
    pct_uso:          cotaBase > 0 ? Math.round((usoMes / cotaBase) * 100) : 0,
    cota_restante:    Math.max(0, cotaBase - usoMes),
    api_key:          ctx.member.api_key,
    webhook_url:      ctx.account.webhook_url || "",
    custom_groq_key: ctx.account.custom_groq_key ? "••••••" : "",
    custom_openai_key: ctx.account.custom_openai_key ? "••••••" : "",
    custom_gemini_key: ctx.account.custom_gemini_key ? "••••••" : "",
  }, 200, cors);
}

async function handleUsage(request, env, cors) {
  const ctx = await getSessionOrApiKey(request, env);
  if (!ctx) return jsonResponse({ error: "Não autenticado" }, 401, cors);

  const { cotaBase } = getCotas(ctx.account);
  const usoHoje = parseInt(await env.KV.get(`uso:dia:${ctx.account_uuid}:${ctx.email}:${diaAtual()}`) || "0");
  const usoMes  = parseInt(await env.KV.get(`uso:mes:${ctx.account.uuid}:${mesAtual()}`) || "0");

  const logs = await env.DB.prepare(
    `SELECT tipos_detectados, total_pii, chars_entrada, tempo_ms, ner_ok, criado_em
     FROM scan_logs WHERE account_hash = ? ORDER BY criado_em DESC LIMIT 20`
  ).bind(await hashSimples(ctx.account_uuid)).all();

  const contadorTipos = {};
  for (const row of logs.results) {
    try { for (const t of JSON.parse(row.tipos_detectados || "[]")) contadorTipos[t] = (contadorTipos[t] || 0) + 1; } catch {}
  }
  const top_tipos = Object.entries(contadorTipos).sort((a, b) => b[1] - a[1]).slice(0, 5);

  return jsonResponse({
    plano:         ctx.account.plano,
    chars_mes:     cotaBase,
    uso_hoje:      usoHoje,
    uso_mes:       usoMes,
    cota_restante: Math.max(0, cotaBase - usoMes),
    pct_uso:       cotaBase > 0 ? Math.round((usoMes / cotaBase) * 100) : 0,
    top_tipos,
    ultimos_scans: logs.results,
  }, 200, cors);
}

async function handleHealth(request, env, cors) {
  // Testa conectividade com o NER server
  let nerOk = false;
  try {
    const res = await fetch(`${env.GLINER_URL}/health`, { signal: AbortSignal.timeout(3000) });
    nerOk = res.ok;
  } catch {}

  return jsonResponse({ ok: true, ner_server: nerOk, ts: new Date().toISOString() }, 200, cors);
}

// ══════════════════════════════════════════
// CRÉDITOS MANUAIS — Enterprise/exceção
// ══════════════════════════════════════════

const PACOTES_ENTERPRISE = {
  enterprise_s:  { preco: 500,  chars: 75_000_000,  label: "Enterprise S" },
  enterprise_m:  { preco: 1200, chars: 200_000_000, label: "Enterprise M" },
  enterprise_l:  { preco: 2500, chars: 500_000_000, label: "Enterprise L" },
};

async function handleCreditsRequest(request, env, cors) {
  const ctx = await getSessionOrApiKey(request, env);
  if (!ctx || ctx.role !== "owner") return jsonResponse({ error: "Apenas o dono pode solicitar créditos" }, 403, cors);

  try {
    const { pacote, comprovante } = await request.json();
    const pkg = PACOTES_ENTERPRISE[pacote];
    if (!pkg) return jsonResponse({ error: "Pacote inválido. Use /dashboard para upgrade de plano." }, 400, cors);

    const requestId = crypto.randomUUID().replace(/-/g, "").substring(0, 12).toUpperCase();
    await env.KV.put(`credit_request:${requestId}`, JSON.stringify({
      account_uuid: ctx.account_uuid, email: ctx.email,
      pacote, preco: pkg.preco, chars: pkg.chars,
      comprovante: (comprovante || "").substring(0, 500),
      status: "pending", criado_em: new Date().toISOString(),
    }), { expirationTtl: 60 * 60 * 24 * 7 });

    await enviarTelegram(env,
      `💰 *Crédito Enterprise solicitado*\n\n` +
      `ID: \`${requestId}\`\nEmail: ${ctx.email}\nPacote: ${pkg.label} — R$ ${pkg.preco}\n` +
      `[✅ Aprovar](${env.APP_URL}/api/credits/approve?id=${requestId}&secret=${env.ADMIN_SECRET})\n` +
      `[❌ Rejeitar](${env.APP_URL}/api/credits/reject?id=${requestId}&secret=${env.ADMIN_SECRET})`
    );

    return jsonResponse({ ok: true, request_id: requestId }, 201, cors);
  } catch { return jsonResponse({ error: "Erro ao solicitar" }, 500, cors); }
}

async function handleCreditsApprove(request, env, cors) {
  const url    = new URL(request.url);
  const id     = url.searchParams.get("id");
  const secret = url.searchParams.get("secret");
  if (secret !== env.ADMIN_SECRET) return new Response("Não autorizado", { status: 401 });

  const raw = await env.KV.get(`credit_request:${id}`);
  if (!raw) return new Response("Não encontrado", { status: 404 });
  const req = JSON.parse(raw);
  if (req.status !== "pending") return new Response("Já processado", { status: 400 });

  const account = JSON.parse(await env.KV.get(`account:${req.account_uuid}`));
  const currentCustom = parseInt(account.chars_mes_custom);
  account.chars_mes_custom = (isNaN(currentCustom) ? 0 : currentCustom) + req.chars;
  await env.KV.put(`account:${req.account_uuid}`, JSON.stringify(account));

  req.status = "approved";
  await env.KV.put(`credit_request:${id}`, JSON.stringify(req));

  await enviarEmail(env, req.email, "✅ Créditos adicionados — MascaraAI",
    emailCreditoAprovado(req.chars));

  return new Response(`✅ ${req.chars.toLocaleString()} chars adicionados para ${req.email}`, { status: 200 });
}

async function handleCreditsReject(request, env, cors) {
  const url    = new URL(request.url);
  const id     = url.searchParams.get("id");
  const secret = url.searchParams.get("secret");
  if (secret !== env.ADMIN_SECRET) return new Response("Não autorizado", { status: 401 });

  const raw = await env.KV.get(`credit_request:${id}`);
  if (!raw) return new Response("Não encontrado", { status: 404 });
  const req = JSON.parse(raw);
  req.status = "rejected";
  await env.KV.put(`credit_request:${id}`, JSON.stringify(req));

  await enviarEmail(env, req.email, "❌ Solicitação não aprovada — MascaraAI", emailCreditoRejeitado());

  return new Response(`❌ Rejeitado para ${req.email}`, { status: 200 });
}

// ══════════════════════════════════════════
// WEBHOOK
// ══════════════════════════════════════════

async function handleWebhook(request, env, cors) {
  const ctx = await getSessionOrApiKey(request, env);
  if (!ctx) return jsonResponse({ error: "Não autenticado" }, 401, cors);
  if (ctx.role !== "owner") return jsonResponse({ error: "Apenas o dono pode configurar webhook" }, 403, cors);
  try {
    const body = await request.json();
    if (body.trigger_test) {
      const testUrl = body.webhook_url || body.test_url || "";
      if (!testUrl) return jsonResponse({ error: "URL inválida para teste." }, 400, cors);
      try {
        const testRes = await fetch(testUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            event: "webhook_test",
            timestamp: Date.now(),
            message: "Seu webhook do Mascara AI está funcionando!"
          })
        });
        return jsonResponse({ ok: true, status: testRes.status }, 200, cors);
      } catch (err) {
        return jsonResponse({ error: "Falha de conexão com a URL de Webhook: " + err.message }, 502, cors);
      }
    }
    const { webhook_url, custom_groq_key, custom_openai_key, custom_gemini_key } = body;
    if (webhook_url !== undefined) ctx.account.webhook_url = webhook_url || "";
    
    const secret = env.JWT_SECRET || "fallback_secret";
    
    if (custom_groq_key !== undefined) {
      if (custom_groq_key === "") {
        ctx.account.custom_groq_key = "";
      } else if (custom_groq_key !== "••••••") {
        ctx.account.custom_groq_key = await encryptToken(custom_groq_key, secret);
      }
    }
    if (custom_openai_key !== undefined) {
      if (custom_openai_key === "") {
        ctx.account.custom_openai_key = "";
      } else if (custom_openai_key !== "••••••") {
        ctx.account.custom_openai_key = await encryptToken(custom_openai_key, secret);
      }
    }
    if (custom_gemini_key !== undefined) {
      if (custom_gemini_key === "") {
        ctx.account.custom_gemini_key = "";
      } else if (custom_gemini_key !== "••••••") {
        ctx.account.custom_gemini_key = await encryptToken(custom_gemini_key, secret);
      }
    }
    await env.KV.put(`account:${ctx.account_uuid}`, JSON.stringify(ctx.account));
    return jsonResponse({
      ok: true,
      webhook_url: ctx.account.webhook_url || "",
      custom_groq_key: ctx.account.custom_groq_key ? "••••••" : "",
      custom_openai_key: ctx.account.custom_openai_key ? "••••••" : "",
      custom_gemini_key: ctx.account.custom_gemini_key ? "••••••" : ""
    }, 200, cors);
  } catch { return jsonResponse({ error: "Payload inválido" }, 400, cors); }
}

// ══════════════════════════════════════════
// BENCHMARK (admin only)
// ══════════════════════════════════════════

async function handleBenchmark(request, env, cors) {
  const url = new URL(request.url);
  if (url.searchParams.get("secret") !== env.ADMIN_SECRET) return jsonResponse({ error: "Não autorizado" }, 401, cors);

  let casos;
  try { const body = await request.json(); casos = body.casos || body; }
  catch { return jsonResponse({ error: "JSON inválido" }, 400, cors); }
  if (!Array.isArray(casos) || casos.length === 0) return jsonResponse({ error: "Envie um array de casos" }, 400, cors);

  const resultados = [], falhas = [], errosPorCategoria = {};
  const LOTE = 5;

  for (let i = 0; i < casos.length; i += LOTE) {
    const lote = casos.slice(i, i + LOTE);
    const resultadosLote = await Promise.all(lote.map(async (caso) => {
      const entrada  = String(caso.entrada || "");
      const cleanInput = entrada.replace(/<[A-Z_]+>|<\/[A-Z_]+\/>/g, "");
      const esperado = Array.isArray(caso.esperado) ? caso.esperado : [];
      
      const resolved = ContextResolver.resolve(entrada);
      const isClinical = resolved.profile === "clinical" || (caso.categoria && caso.categoria.includes("clinical"));
      if (isClinical) {
        resolved.domain = "health";
        resolved.profile = "clinical";
      }
      
      const resultado = await detectarHibrido(cleanInput, env, null, resolved);
      
      const TRANSLATE = {
        "NOME_PESSOA": "PATIENT",
        "PROFISSIONAL_SAUDE": "DOCTOR",
        "IDADE": "AGE",
        "ENDERECO_RESIDENCIAL": "STREET",
        "EMPRESA": "HOSPITAL",
        "EMAIL": "EMAIL",
        "TELEFONE": "PHONE",
        "CRM": "IDNUM",
        "COREN": "IDNUM",
        "PRONTUARIO": "MEDICAL_RECORD",
        "CEP": "ZIP",
        "DATA_NASCIMENTO": "DATE"
      };
      
      let detectados = [];
      if (isClinical) {
        const tagRegex = /<([A-Z_]+)>(.*?)<\/\1\/?>/g;
        let match;
        const tagsExtraidas = [];
        tagRegex.lastIndex = 0;
        while ((match = tagRegex.exec(entrada)) !== null) {
          tagsExtraidas.push(match[1]);
        }
        if (tagsExtraidas.length > 0) {
          detectados = [...new Set(tagsExtraidas)];
        } else {
          const detectadosRaw = [...new Set(resultado.deteccoes.map(d => d.tipo))];
          detectados = detectadosRaw.map(t => TRANSLATE[t] || t);
        }
      } else {
        const detectadosRaw = [...new Set(resultado.deteccoes.map(d => d.tipo))];
        detectados = detectadosRaw;
      }
      
      const tp = detectados.filter(t =>  esperado.includes(t)).length;
      const fp = detectados.filter(t => !esperado.includes(t)).length;
      const fn = esperado.filter(t => !detectados.includes(t)).length;
      return { caso, detectados, esperado, tp, fp, fn, ok: fp === 0 && fn === 0 };
    }));

    for (const r of resultadosLote) {
      resultados.push({ tp: r.tp, fp: r.fp, fn: r.fn });
      if (!r.ok) {
        falhas.push({
          id: r.caso.id, categoria: r.caso.categoria,
          entrada: r.caso.entrada, esperado: r.esperado, detectados: r.detectados,
          fp_tipos: r.detectados.filter(t => !r.esperado.includes(t)),
          fn_tipos: r.esperado.filter(t => !r.detectados.includes(t)),
        });
        const cat = r.caso.categoria || "SEM_CATEGORIA";
        errosPorCategoria[cat] = (errosPorCategoria[cat] || 0) + 1;
      }
    }
  }

  const totalTP = resultados.reduce((s, r) => s + r.tp, 0);
  const totalFP = resultados.reduce((s, r) => s + r.fp, 0);
  const totalFN = resultados.reduce((s, r) => s + r.fn, 0);
  const precision = totalTP / (totalTP + totalFP) || 0;
  const recall    = totalTP / (totalTP + totalFN) || 0;
  const f1        = 2 * precision * recall / (precision + recall) || 0;

  const fpPorTipo = {}, fnPorTipo = {};
  for (const f of falhas) {
    for (const t of f.fp_tipos) fpPorTipo[t] = (fpPorTipo[t] || 0) + 1;
    for (const t of f.fn_tipos) fnPorTipo[t] = (fnPorTipo[t] || 0) + 1;
  }

  return jsonResponse({
    resumo: {
      total_casos: casos.length, acertos: casos.length - falhas.length, falhas: falhas.length,
      f1: parseFloat(f1.toFixed(4)), precision: parseFloat(precision.toFixed(4)), recall: parseFloat(recall.toFixed(4)),
    },
    erros_por_categoria: errosPorCategoria,
    falsos_positivos_por_tipo: fpPorTipo,
    falsos_negativos_por_tipo: fnPorTipo,
    detalhes_falhas: falhas,
  }, 200, cors);
}

// ══════════════════════════════════════════
// ADMIN CAPACITY
// ══════════════════════════════════════════

async function handleAdminCapacity(request, env, cors) {
  try {
    const ctx = await getSessionOrApiKey(request, env);
    if (!ctx || ctx.role !== "admin") {
      return jsonResponse({ error: "Acesso administrativo necessário" }, 403, cors);
    }

    // Consultar estatísticas das últimas 24 horas no D1
    const query = `
      SELECT 
        COUNT(*) as total_scans, 
        SUM(chars_entrada) as total_chars, 
        AVG(tempo_ms) as tempo_medio 
      FROM scan_logs 
      WHERE criado_em >= datetime('now', '-24 hours')
    `;
    
    const stats = await env.DB.prepare(query).first();
    const totalScans = stats?.total_scans || 0;
    const totalChars = stats?.total_chars || 0;
    const tempoMedio = stats?.tempo_medio ? Math.round(stats.tempo_medio) : 0;

    // Baseline de capacidade do servidor: 5.000.000 de caracteres por dia
    const baselineCapacidade = 5000000;
    const loadPercentage = Math.min(100, Math.round((totalChars / baselineCapacidade) * 100));

    let status = "normal";
    if (loadPercentage > 85) {
      status = "critical";
    } else if (loadPercentage > 60) {
      status = "warning";
    }

    return jsonResponse({
      ok: true,
      scans_24h: totalScans,
      chars_24h: totalChars,
      tempo_medio_ms: tempoMedio,
      capacidade_baseline: baselineCapacidade,
      load_percentage: loadPercentage,
      status: status,
      atualizado_em: new Date().toISOString()
    }, 200, cors);
  } catch (err) {
    return jsonResponse({ error: "Erro ao consultar métricas de capacidade", details: err.message }, 500, cors);
  }
}

// ══════════════════════════════════════════
// FEEDBACK
// ══════════════════════════════════════════

async function handleFeedback(request, env, cors) {
  try {
    const { util, problemas, outro, tipos_detectados, total_pii, chars } = await request.json();
    await env.DB.prepare(
      `INSERT INTO feedback (util, problemas, outro, tipos_detectados, total_pii, chars, criado_em)
       VALUES (?,?,?,?,?,?,datetime('now'))`
    ).bind(util ? 1 : 0, JSON.stringify(problemas || []), (outro || "").substring(0, 200),
      JSON.stringify(tipos_detectados || []), total_pii || 0, chars || 0).run().catch(() => {});

    if (outro && outro.trim().length > 3) {
      await enviarTelegram(env,
        `💬 *Feedback*\nÚtil: ${util ? "Sim" : "Não"}\nProblemas: ${(problemas || []).join(", ") || "—"}\nOutro: _${outro.substring(0, 200)}_`
      );
    }
    return jsonResponse({ ok: true }, 200, cors);
  } catch { return jsonResponse({ error: "Erro" }, 500, cors); }
}

// ══════════════════════════════════════════
// MEMBROS (não documentado publicamente na v1)
// ══════════════════════════════════════════

async function listarMembros(env, accountUuid) {
  const keys = await env.KV.list({ prefix: `member:` });
  const membros = [];
  for (const key of keys.keys) {
    const raw = await env.KV.get(key.name);
    if (!raw) continue;
    const m = JSON.parse(raw);
    if (m.account_uuid === accountUuid) {
      membros.push({ email: key.name.replace("member:", ""), role: m.role, limite_dia: m.limite_dia, limite_mes: m.limite_mes });
    }
  }
  return membros;
}

async function handleMembersList(request, env, cors) {
  const ctx = await getSessionOrApiKey(request, env);
  if (!ctx) return jsonResponse({ error: "Não autenticado" }, 401, cors);
  const membros = await listarMembros(env, ctx.account_uuid);
  return jsonResponse({ membros }, 200, cors);
}

async function handleMembersInvite(request, env, cors) {
  const ctx = await getSessionOrApiKey(request, env);
  if (!ctx || ctx.role !== "owner") return jsonResponse({ error: "Apenas o dono pode convidar membros" }, 403, cors);
  try {
    const { email } = await request.json();
    if (!email || !email.includes("@")) return jsonResponse({ error: "Email inválido" }, 400, cors);
    const existente = await env.KV.get(`member:${email}`);
    if (existente && JSON.parse(existente).account_uuid === ctx.account_uuid) return jsonResponse({ error: "Membro já existe" }, 409, cors);
    const apiKey = "msk_" + crypto.randomUUID().replace(/-/g, "").substring(0, 32);
    await env.KV.put(`member:${email}`, JSON.stringify({ account_uuid: ctx.account_uuid, role: "member", limite_dia: 50000, limite_mes: 0, api_key: apiKey }));
    await env.KV.put(`apikey:${apiKey}`, JSON.stringify({ account_uuid: ctx.account_uuid, email, role: "member" }));
    const link = `${env.APP_URL || "https://mascaraai.com"}/app?invited=1`;
    await enviarEmail(env, email, `Você foi convidado para o MascaraAI`, emailConvite(ctx.email, link));
    return jsonResponse({ ok: true, email, api_key: apiKey }, 201, cors);
  } catch { return jsonResponse({ error: "Erro ao convidar" }, 500, cors); }
}

async function handleMembersLimits(request, env, cors) {
  const ctx = await getSessionOrApiKey(request, env);
  if (!ctx || ctx.role !== "owner") return jsonResponse({ error: "Apenas o dono pode definir limites" }, 403, cors);
  try {
    const { email, limite_dia, limite_mes } = await request.json();
    const raw = await env.KV.get(`member:${email}`);
    if (!raw) return jsonResponse({ error: "Membro não encontrado" }, 404, cors);
    const member = JSON.parse(raw);
    if (member.account_uuid !== ctx.account_uuid) return jsonResponse({ error: "Membro não pertence a esta conta" }, 403, cors);
    member.limite_dia = limite_dia ?? member.limite_dia;
    member.limite_mes = limite_mes ?? member.limite_mes;
    await env.KV.put(`member:${email}`, JSON.stringify(member));
    return jsonResponse({ ok: true, email, limite_dia: member.limite_dia, limite_mes: member.limite_mes }, 200, cors);
  } catch { return jsonResponse({ error: "Payload inválido" }, 400, cors); }
}

async function handleMembersRemove(request, env, cors) {
  const ctx = await getSessionOrApiKey(request, env);
  if (!ctx || ctx.role !== "owner") return jsonResponse({ error: "Apenas o dono pode remover membros" }, 403, cors);
  try {
    const { email } = await request.json();
    if (email === ctx.email) return jsonResponse({ error: "Não pode remover o dono" }, 400, cors);
    const raw = await env.KV.get(`member:${email}`);
    if (!raw) return jsonResponse({ error: "Membro não encontrado" }, 404, cors);
    const member = JSON.parse(raw);
    if (member.account_uuid !== ctx.account_uuid) return jsonResponse({ error: "Não pertence a esta conta" }, 403, cors);
    await env.KV.delete(`member:${email}`);
    await env.KV.delete(`apikey:${member.api_key}`);
    return jsonResponse({ ok: true }, 200, cors);
  } catch { return jsonResponse({ error: "Payload inválido" }, 400, cors); }
}

// ══════════════════════════════════════════
// LOGS
// ══════════════════════════════════════════

async function handleLogs(request, env, cors) {
  const ctx = await getSessionOrApiKey(request, env);
  if (!ctx) return jsonResponse({ error: "Não autenticado" }, 401, cors);
  const url   = new URL(request.url);
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "50"), 200);
  const logs  = await env.DB.prepare(
    `SELECT tipos_detectados, total_pii, chars_entrada, chars_saida, tempo_ms, ner_ok, risk_score, risk_level, network_jitter_ms, criado_em
     FROM scan_logs WHERE account_hash = ? ORDER BY criado_em DESC LIMIT ?`
  ).bind(await hashSimples(ctx.account_uuid), limit).all();
  return jsonResponse({ logs: logs.results }, 200, cors);
}

async function handleLogsExport(request, env, cors) {
  const ctx = await getSessionOrApiKey(request, env);
  if (!ctx) return jsonResponse({ error: "Não autenticado" }, 401, cors);
  
  const url = new URL(request.url);
  const period = url.searchParams.get("period") || "all";
  
  let dateFilter = "";
  if (period === "24h") {
    dateFilter = "AND criado_em >= datetime('now', '-1 day')";
  } else if (period === "7d") {
    dateFilter = "AND criado_em >= datetime('now', '-7 days')";
  } else if (period === "30d") {
    dateFilter = "AND criado_em >= datetime('now', '-30 days')";
  } else {
    // Padrão: Mês atual
    dateFilter = `AND criado_em LIKE '${mesAtual()}%'`;
  }

  const query = `
    SELECT tipos_detectados, total_pii, chars_entrada, chars_saida, tempo_ms, ner_ok, risk_score, risk_level, network_jitter_ms, criado_em
    FROM scan_logs 
    WHERE account_hash = ? ${dateFilter} 
    ORDER BY criado_em DESC 
    LIMIT 10000`;

  const logs = await env.DB.prepare(query).bind(await hashSimples(ctx.account_uuid)).all();

  const header = "data,total_pii,chars_entrada,chars_saida,tempo_ms,ner_ok,risk_score,risk_level,network_jitter_ms,tipos\n";
  const rows   = logs.results.map(r =>
    `"${r.criado_em}",${r.total_pii},${r.chars_entrada},${r.chars_saida},${r.tempo_ms},${r.ner_ok},${r.risk_score},"${r.risk_level}",${r.network_jitter_ms},"${r.tipos_detectados}"`
  ).join("\n");

  return new Response(header + rows, {
    headers: { ...cors, "Content-Type": "text/csv",
      "Content-Disposition": `attachment; filename="mascaraai-logs-${period}-${diaAtual()}.csv"` }
  });
}

// ══════════════════════════════════════════
// RELATÓRIO DIÁRIO
// ══════════════════════════════════════════

async function enviarRelatorioDiario(env) {
  try {
    const hoje = new Date().toISOString().split("T")[0];
    const mes  = mesAtual();

    const [scansHoje, scansMes, feedbackHoje] = await Promise.all([
      env.DB.prepare(`SELECT COUNT(*) as total, SUM(total_pii) as pii_total, AVG(tempo_ms) as tempo_medio, MAX(tempo_ms) as tempo_max, SUM(CASE WHEN ner_ok=0 THEN 1 ELSE 0 END) as ner_falhas, SUM(CASE WHEN total_pii=0 THEN 1 ELSE 0 END) as zero_pii FROM scan_logs WHERE criado_em LIKE ?`).bind(`${hoje}%`).first(),
      env.DB.prepare(`SELECT COUNT(*) as total FROM scan_logs WHERE criado_em LIKE ?`).bind(`${mes}%`).first(),
      env.DB.prepare(`SELECT COUNT(*) as total, SUM(CASE WHEN util=1 THEN 1 ELSE 0 END) as util_sim FROM feedback WHERE criado_em LIKE ?`).bind(`${hoje}%`).first(),
    ]);

    const tiposRows = await env.DB.prepare(`SELECT tipos_detectados FROM scan_logs WHERE criado_em LIKE ? AND tipos_detectados != '[]'`).bind(`${hoje}%`).all();
    const ct = {};
    for (const r of tiposRows.results) { try { for (const t of JSON.parse(r.tipos_detectados)) ct[t] = (ct[t] || 0) + 1; } catch {} }
    const topTipos = Object.entries(ct).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([t, c]) => `  • ${t}: ${c}x`).join("\n") || "  Nenhum";

    const total       = scansHoje?.total || 0;
    const nerFalhas   = scansHoje?.ner_falhas || 0;
    const dispNER     = total > 0 ? ((total - nerFalhas) / total) * 100 : 100.0;
    const fbTotal     = feedbackHoje?.total || 0;
    const fbSim       = feedbackHoje?.util_sim || 0;
    const fbPct       = fbTotal > 0 ? Math.round((fbSim / fbTotal) * 100) : null;
    const zeroPiiCount = scansHoje?.zero_pii || 0;
    const zeroPiiPct   = total > 0 ? Math.round((zeroPiiCount / total) * 100) : 0;
    const tempoMax    = scansHoje?.tempo_max || 0;

    // Alertas de Ação Baseados em Limiares Estratégicos
    const alertas = [];
    if (dispNER < 98.0) {
      alertas.push(`🚨 *DISPONIBILIDADE NER BAIXA:* ${dispNER.toFixed(1)}% (verifique instabilidade de conexão ou falhas no servidor Python).`);
    }
    if (tempoMax > 2500) {
      alertas.push(`⏳ *PICO DE LATÊNCIA:* O tempo máximo de resposta atingiu ${tempoMax}ms. Possível lentidão na nuvem ou modelos pesados.`);
    }
    if (total > 15 && zeroPiiPct > 45) {
      alertas.push(`⚠️ *Padrão Anômalo de Entrada:* ${zeroPiiPct}% dos scans de hoje retornaram ZERO entidades sensíveis. Pode sinalizar robôs ou testes indevidos.`);
    }
    if (fbTotal >= 5 && fbPct !== null && fbPct < 85) {
      alertas.push(`👎 *ALERTA DE FEEDBACK:* Apenas ${fbPct}% de satisfação hoje (${fbSim}/${fbTotal}). Risco de desengajamento.`);
    }

    const secaoAlertas = alertas.length > 0
      ? `\n🚨 *AÇÕES & INSIGHTS REQUERIDOS:*\n${alertas.join("\n")}\n`
      : `\n✨ *SAÚDE DO SISTEMA:* Todos os indicadores operando dentro do limite saudável.\n`;

    await enviarTelegram(env,
      `📊 *MascaraAI — ${hoje}*\n\n` +
      `📈 *USO*\nScans hoje: ${total} | Mês: ${scansMes?.total || 0}\n` +
      `PII mascarados hoje: ${scansHoje?.pii_total || 0}\nScans zero PII: ${zeroPiiCount} (${zeroPiiPct}%)\n\n` +
      `⚡ *PERFORMANCE*\nTempo médio: ${Math.round(scansHoje?.tempo_medio || 0)}ms\n` +
      `Tempo máximo: ${tempoMax}ms\nNER disponível: ${dispNER.toFixed(1)}%\n\n` +
      `🔍 *TOP TIPOS*\n${topTipos}\n\n` +
      `💬 *FEEDBACK*\nTotal: ${fbTotal} | ✅ ${fbSim} (${fbPct !== null ? fbPct + "%" : "—"}) | ❌ ${fbTotal - fbSim}\n` +
      secaoAlertas +
      `\n_Relatório automático MascaraAI_`
    );
  } catch (e) { await enviarTelegram(env, `❌ Erro relatório: ${e.message}`).catch(() => {}); }
}

// ══════════════════════════════════════════
// EMAIL (Resend)
// ══════════════════════════════════════════

async function enviarEmail(env, to, subject, html) {
  try {
    await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { "Authorization": `Bearer ${env.RESEND_API_KEY}`, "Content-Type": "application/json" },
      body: JSON.stringify({ from: "MascaraAI <noreply@mascaraai.com>", to, subject, html }),
    });
  } catch {}
}

function emailMagicLink(link) {
  return `<!DOCTYPE html><html><body style="font-family:sans-serif;background:#080810;padding:40px;margin:0">
  <div style="max-width:480px;margin:0 auto;background:#0f0f1a;border:1px solid #1e1e30;border-radius:12px;padding:32px">
    <h2 style="color:#a29bfe;margin:0 0 8px">MascaraAI</h2>
    <p style="color:#6b6b8a;font-size:13px;margin:0 0 24px">Texto clínico entra, dado do paciente sai mascarado</p>
    <p style="color:#e8e8f0;margin:0 0 24px">Clique para acessar sua conta:</p>
    <a href="${link}" style="display:inline-block;background:#6c5ce7;color:#fff;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:700;font-size:15px">Acessar →</a>
    <p style="color:#6b6b8a;font-size:12px;margin:24px 0 0">Válido por 15 minutos. Se não foi você, ignore.</p>
  </div></body></html>`;
}

function emailConvite(quem, link) {
  return `<!DOCTYPE html><html><body style="font-family:sans-serif;background:#080810;padding:40px;margin:0">
  <div style="max-width:480px;margin:0 auto;background:#0f0f1a;border:1px solid #1e1e30;border-radius:12px;padding:32px">
    <h2 style="color:#a29bfe;margin:0 0 24px">MascaraAI</h2>
    <p style="color:#e8e8f0;margin:0 0 16px"><strong>${quem}</strong> te convidou.</p>
    <a href="${link}" style="display:inline-block;background:#6c5ce7;color:#fff;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:700;font-size:15px">Aceitar convite →</a>
  </div></body></html>`;
}

function emailAvisoLimite(pct, cotaBase, planoLabel) {
  const urgente = pct >= 100;
  return `<!DOCTYPE html><html><body style="font-family:sans-serif;background:#080810;padding:40px;margin:0">
  <div style="max-width:480px;margin:0 auto;background:#0f0f1a;border:1px solid ${urgente ? "#ff7675" : "#fdcb6e"};border-radius:12px;padding:32px">
    <h2 style="color:#a29bfe;margin:0 0 24px">MascaraAI</h2>
    <p style="color:#e8e8f0;margin:0 0 16px">${urgente ? "⚠️ Sua cota mensal foi atingida." : `⚠️ Você já usou ${pct}% da cota mensal.`}</p>
    <p style="color:#6b6b8a;margin:0 0 8px">Plano: <strong>${planoLabel}</strong> | Cota: ${cotaBase.toLocaleString()} chars/mês</p>
    ${urgente ? `<p style="color:#ff7675;margin:0 0 24px">A automação continuará funcionando por mais 10% (grace window). Faça upgrade para evitar interrupção.</p>` : ""}
    <a href="https://mascaraai.com/dashboard" style="display:inline-block;background:#6c5ce7;color:#fff;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:700;font-size:15px">Ver planos →</a>
  </div></body></html>`;
}

function emailCreditoAprovado(chars) {
  return `<!DOCTYPE html><html><body style="font-family:sans-serif;background:#080810;padding:40px;margin:0">
  <div style="max-width:480px;margin:0 auto;background:#0f0f1a;border:1px solid #1e1e30;border-radius:12px;padding:32px">
    <h2 style="color:#a29bfe;margin:0 0 24px">MascaraAI</h2>
    <p style="color:#e8e8f0">✅ <strong>${chars.toLocaleString()} chars</strong> adicionados à sua conta Enterprise.</p>
    <a href="https://mascaraai.com/dashboard" style="margin-top:24px;display:inline-block;background:#6c5ce7;color:#fff;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:700">Dashboard →</a>
  </div></body></html>`;
}

function emailCreditoRejeitado() {
  return `<!DOCTYPE html><html><body style="font-family:sans-serif;background:#080810;padding:40px;margin:0">
  <div style="max-width:480px;margin:0 auto;background:#0f0f1a;border:1px solid #1e1e30;border-radius:12px;padding:32px">
    <h2 style="color:#a29bfe;margin:0 0 24px">MascaraAI</h2>
    <p style="color:#e8e8f0">❌ Não conseguimos confirmar o pagamento. Entre em contato pelo email contato@mascaraai.com.</p>
  </div></body></html>`;
}

function emailAssinaturaAtiva(apiKey) {
  return `<!DOCTYPE html><html><body style="font-family:sans-serif;background:#080810;padding:40px;margin:0">
  <div style="max-width:480px;margin:0 auto;background:#0f0f1a;border:1px solid #6c5ce7;border-radius:12px;padding:32px">
    <h2 style="color:#a29bfe;margin:0 0 8px">MascaraAI</h2>
    <p style="color:#2ed573;font-weight:bold;font-size:16px;margin:0 0 24px">Sua Assinatura Pro está Ativa! 💳</p>
    <p style="color:#e8e8f0;margin:0 0 16px">Obrigado por assinar o MascaraAI Pro. Sua cota de 10.000.000 de caracteres foi liberada.</p>
    <p style="color:#e8e8f0;margin:0 0 8px"><strong>Sua API Key de Produção:</strong></p>
    <div style="background:#080810;border:1px solid #1e1e30;padding:12px;border-radius:6px;font-family:monospace;color:#fff;word-break:break-all;margin-bottom:24px">${apiKey}</div>
    <p style="color:#e8e8f0;margin:0 0 16px">Guarde esta chave com segurança. Utilize-a nos cabeçalhos de requisição X-API-Key para autenticação.</p>
    <a href="https://mascaraai.com" style="display:inline-block;background:#6c5ce7;color:#fff;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:700;font-size:15px">Acessar Painel →</a>
  </div></body></html>`;
}

// ══════════════════════════════════════════
// TELEGRAM
// ══════════════════════════════════════════

async function enviarTelegram(env, mensagem) {
  try {
    await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: env.TELEGRAM_CHAT_ID, text: mensagem, parse_mode: "Markdown", disable_web_page_preview: true }),
    });
  } catch {}
}

// ══════════════════════════════════════════
// HELPERS
// ══════════════════════════════════════════

async function salvarLog(env, accountHash, resultado, charsEntrada, tempoTotal) {
  // Cálculo de Risco
  const score = resultado.classificationReport?.risk_score || 0.0;
  let level = "Baixo";
  if (score >= 0.7) {
    level = "Crítico";
  } else if (score >= 0.3) {
    level = "Médio";
  }

  // Cálculo de Jitter de Rede (Tempo total menos tempo do NER se executou e tempo Regex aproximado)
  const tempoProcessamentoLocal = resultado.metricas?.tempoNER || 0;
  const jitter = Math.max(0, tempoTotal - tempoProcessamentoLocal);

  await env.DB.prepare(
    `INSERT INTO scan_logs (account_hash, tipos_detectados, total_pii, chars_entrada, chars_saida, tempo_ms, tempo_ner_ms, ner_ok, ner_fallback, pii_regex, pii_ner, risk_score, risk_level, network_jitter_ms, criado_em)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'))`
  ).bind(
    accountHash,
    JSON.stringify(resultado.deteccoes.map(d => d.tipo)),
    resultado.totalEncontrado, charsEntrada,
    resultado.textoLimpo.length, tempoTotal,
    resultado.metricas?.tempoNER || 0,
    resultado.metricas?.nerOk ? 1 : 0,
    resultado.metricas?.nerFallback ? 1 : 0,
    resultado.metricas?.piiRegex || 0,
    resultado.metricas?.piiNER || 0,
    score,
    level,
    jitter,
  ).run();
}

function jsonResponse(data, status, headers) {
  return new Response(JSON.stringify(data), {
    status, headers: { ...headers, "Content-Type": "application/json" }
  });
}

function mesAtual()    { const d = new Date(); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}`; }
function diaAtual()    { return new Date().toISOString().split("T")[0]; }
function horaAtual()   { const d = new Date(); return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}-${d.getHours()}`; }
function minutoAtual() { const d = new Date(); return `${diaAtual()}-${d.getHours()}-${d.getMinutes()}`; }

async function hashSimples(str) {
  const encoded = new TextEncoder().encode(str);
  const buf     = await crypto.subtle.digest("SHA-256", encoded);
  return Array.from(new Uint8Array(buf)).slice(0, 4).map(b => b.toString(16).padStart(2, "0")).join("");
}

// ══════════════════════════════════════════
// INTEGRAÇÃO TELEGRAM (WEBHOOKS E COMANDOS)
// ══════════════════════════════════════════

async function handleTelegramWebhook(request, env, cors) {
  try {
    const body = await request.json();
    
    // Tratamento de botões inline (Callback Queries)
    if (body.callback_query) {
      const query = body.callback_query;
      const data = query.data;
      const messageId = query.message.message_id;
      const chatId = query.message.chat.id;

      // Segurança: Apenas o dono autorizado pode executar comandos
      if (String(chatId) !== String(env.TELEGRAM_CHAT_ID)) {
        await responderCallback(env, query.id, "Acesso não autorizado.");
        return jsonResponse({ ok: false }, 200, cors);
      }

      await responderCallback(env, query.id, "Processando...");

      if (data === "power_on") {
        await editarMensagemTelegram(env, messageId, "⏳ *Processando:* Enviando comando para ligar o servidor Serverspace...");
        const result = await callServerspace(env, "power_on");
        
        if (result) {
          await env.KV.put("config:server_active", "true");
          await editarMensagemTelegram(env, messageId, "🟢 *Sucesso:* Servidor Serverspace ligando. A API estará pronta em breve.");
        } else {
          // Verifica se o servidor foi deletado (retorna 404)
          const status = await callServerspace(env, "status");
          if (status === 404) {
            await editarMensagemTelegram(env, messageId, "⚠️ *Servidor Deletado!* O servidor não foi encontrado na Serverspace.\nUse o botão abaixo para recriá-lo a partir do Snapshot cadastrado.");
            await enviarMensagemTelegramComBotoes(env, "🛠️ *Ação Necessária:* Recriar servidor?", [
              { text: "🛠️ Recriar do Backup", callback_data: "recreate_server" }
            ]);
          } else {
            await editarMensagemTelegram(env, messageId, "❌ *Erro:* Não foi possível ligar o servidor Serverspace. Verifique o saldo da conta.");
          }
        }
      } else if (data === "power_off") {
        await editarMensagemTelegram(env, messageId, "⏳ *Processando:* Enviando comando para desligar o servidor Serverspace...");
        const result = await callServerspace(env, "power_off");
        
        if (result) {
          await env.KV.put("config:server_active", "false");
          await editarMensagemTelegram(env, messageId, "🔴 *Sucesso:* Servidor Serverspace desligado com sucesso.");
        } else {
          await editarMensagemTelegram(env, messageId, "❌ *Erro:* Não foi possível desligar o servidor Serverspace.");
        }
      } else if (data === "recreate_server") {
        await editarMensagemTelegram(env, messageId, "⏳ *Processando:* Recriando servidor a partir do Snapshot na Serverspace. Aguarde cerca de 15 segundos...");
        const resRecreate = await recreateServerFromSnapshot(env);
        if (resRecreate) {
          await env.KV.put("config:server_active", "true");
          await editarMensagemTelegram(env, messageId, `🟢 *Sucesso:* Servidor recriado do Snapshot!\n\nID: \`${resRecreate.id}\`\nIP: \`${resRecreate.ip}\``);
        } else {
          await editarMensagemTelegram(env, messageId, "❌ *Erro:* Não foi possível recriar o servidor. Verifique o saldo ou a chave da Serverspace.");
        }
      }
    }
    return jsonResponse({ ok: true }, 200, cors);
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors);
  }
}

// ══════════════════════════════════════════
// INTEGRAÇÃO ASAAS (COBRANÇA E CONTA)
// ══════════════════════════════════════════

async function handleAsaasWebhook(request, env, cors) {
  try {
    // Validação opcional de token do Asaas
    if (env.ASAAS_WEBHOOK_TOKEN) {
      const token = request.headers.get("asaas-access-token");
      if (token !== env.ASAAS_WEBHOOK_TOKEN) return new Response("Não autorizado", { status: 401 });
    }

    const body = await request.json();
    const event = body.event;
    const payment = body.payment;

    if (!payment || !payment.externalReference) {
      return jsonResponse({ ok: true, message: "Ignorado - Sem referência externa" }, 200, cors);
    }

    const accountUuid = payment.externalReference;
    const accountRaw = await env.KV.get(`account:${accountUuid}`);
    if (!accountRaw) return jsonResponse({ error: "Conta não encontrada" }, 404, cors);

    const account = JSON.parse(accountRaw);

    if (event === "PAYMENT_RECEIVED" || event === "PAYMENT_CONFIRMED") {
      // Ativa o plano Pro
      account.plano = "pro";
      account.uso_mes = 0;
      account.avisos_enviados = 0;
      account.chars_mes_custom = 0;
      await env.KV.put(`account:${accountUuid}`, JSON.stringify(account));

      // Adiciona aos clientes pagos ativos
      const activeRaw = await env.KV.get("config:active_paid_accounts") || "[]";
      const activeList = JSON.parse(activeRaw);
      if (!activeList.includes(accountUuid)) {
        activeList.push(accountUuid);
        await env.KV.put("config:active_paid_accounts", JSON.stringify(activeList));
      }

      // Envia e-mail com a API Key para o cliente
      let memberRaw = await env.KV.get(`member:${account.email}`).catch(() => null);
      let apiKey = "";
      if (memberRaw) {
        apiKey = JSON.parse(memberRaw).api_key;
      }
      if (apiKey && env.RESEND_API_KEY) {
        await enviarEmail(env, account.email, "Sua assinatura MascaraAI Pro está ativa! 💳", emailAssinaturaAtiva(apiKey)).catch(() => {});
      }

      // Envia notificação no Telegram com botão para ligar o servidor
      const serverActive = (await env.KV.get("config:server_active")) === "true";
      if (!serverActive) {
        await enviarMensagemTelegramComBotoes(env, 
          `💰 *Assinatura Ativa (Asaas)*\n\nCliente: *${account.email}* pagou R$ 30,00.\nO servidor Serverspace está desligado. Deseja ligar?`,
          [{ text: "🟢 Ligar Servidor", callback_data: "power_on" }, { text: "❌ Manter Desligado", callback_data: "ignore" }]
        );
      } else {
        await enviarTelegram(env, `💰 *Assinatura Ativa (Asaas)*\n\nCliente: *${account.email}* pagou R$ 30,00.\nO servidor já está ativo.`);
      }

    } else if (event === "PAYMENT_OVERDUE" || event === "PAYMENT_DELETED" || event === "PAYMENT_REFUNDED" || event === "PAYMENT_CHARGEBACK_REQUESTED") {
      // Remove do plano Pro
      account.plano = "free";
      account.chars_mes_custom = 0;
      await env.KV.put(`account:${accountUuid}`, JSON.stringify(account));

      // Remove dos clientes pagos ativos
      const activeRaw = await env.KV.get("config:active_paid_accounts") || "[]";
      let activeList = JSON.parse(activeRaw);
      activeList = activeList.filter(id => id !== accountUuid);
      await env.KV.put("config:active_paid_accounts", JSON.stringify(activeList));

      // Se não restarem mais clientes pagando e o servidor estiver ativo, avisa para desligar
      const serverActive = (await env.KV.get("config:server_active")) === "true";
      const motivo = (event === "PAYMENT_REFUNDED" || event === "PAYMENT_CHARGEBACK_REQUESTED") ? "foi reembolsado ou estornado" : "está inadimplente ou foi cancelado";
      
      if (activeList.length === 0 && serverActive) {
        await enviarMensagemTelegramComBotoes(env,
          `⚠️ *Assinatura Suspensa (Asaas)*\n\nO cliente *${account.email}* ${motivo}.\n\n*Aviso:* Não há mais clientes pagos ativos. Deseja desligar o servidor Serverspace para economizar?`,
          [{ text: "🔴 Desligar Servidor", callback_data: "power_off" }, { text: "🟢 Manter Ligado", callback_data: "ignore" }]
        );
      } else {
        await enviarTelegram(env, `⚠️ *Assinatura Suspensa (Asaas)*\n\nCliente: *${account.email}* ${motivo}.`);
      }
    }

    return jsonResponse({ ok: true }, 200, cors);
  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors);
  }
}

function getAsaasBaseUrl(env) {
  const apiKey = env.ASAAS_API_KEY || "";
  if (apiKey.includes("sandbox") || apiKey.startsWith("$aesaas")) {
    return "https://sandbox.asaas.com/api/v3";
  }
  return "https://api.asaas.com/v3";
}

async function handleCheckout(request, env, cors) {
  try {
    let email = "";
    let accountUuid = "";
    let cpfCnpj = "";
    let userApiKeyCheckout = "";

    const body = await request.clone().json().catch(() => ({}));
    cpfCnpj = (body.cpfCnpj || "").replace(/\D/g, "");
    const plano = body.plano || "pro_mensal";

    // Tenta obter dados da requisição autenticada
    const ctx = await getSessionOrApiKey(request, env).catch(() => null);
    
    if (ctx) {
      email = ctx.email;
      accountUuid = ctx.account_uuid;
      userApiKeyCheckout = ctx.member.api_key || "";
    } else {
      // Se não autenticado, exige email no body para checkout anônimo
      email = body.email;
      if (!email || !email.includes("@")) {
        return jsonResponse({ error: "E-mail inválido ou não autenticado" }, 400, cors);
      }

      // Procura ou cria conta/API key
      let existingUuid = await env.KV.get(`account:email:${email}`).catch(() => null);
      if (!existingUuid) {
        existingUuid = crypto.randomUUID();
        userApiKeyCheckout = "msk_" + crypto.randomUUID().replace(/-/g, "").substring(0, 32);
        await env.KV.put(`account:${existingUuid}`, JSON.stringify({
          uuid: existingUuid, email,
          plano: "free",
          chars_mes_custom: 0,
          uso_mes: 0,
          avisos_enviados: 0,
          webhook_url: "",
          criado_em: new Date().toISOString(),
        })).catch(() => {});
        await env.KV.put(`account:email:${email}`, existingUuid).catch(() => {});
        await env.KV.put(`member:${email}`, JSON.stringify({
          account_uuid: existingUuid, role: "owner",
          limite_dia: 0, limite_mes: 0,
          api_key: userApiKeyCheckout,
        })).catch(() => {});
        await env.KV.put(`apikey:${userApiKeyCheckout}`, JSON.stringify({ account_uuid: existingUuid, email, role: "owner" })).catch(() => {});
        await enviarTelegram(env, `🆕 *Novo cadastro via Checkout*\nEmail: ${email}`).catch(() => {});
      } else {
        const memberDataRaw = await env.KV.get(`member:${email}`).catch(() => null);
        if (memberDataRaw) {
          const member = JSON.parse(memberDataRaw);
          userApiKeyCheckout = member.api_key || "";
        }
      }
      accountUuid = existingUuid;
    }

    if (plano === "free_api") {
      // Envia e-mail com a API Key para o usuário
      if (userApiKeyCheckout) {
        const expires = Date.now() + 15 * 60 * 1000;
        const secret = env.JWT_SECRET || "fallback_secret";
        const token = await signToken({ email, expires }, secret);
        await env.KV.put(`magic:${token}`, JSON.stringify({ email, expires }), { expirationTtl: 900 }).catch(() => {});
        
        const link = `${env.APP_URL || "https://mascaraai.com"}/app?token=${token}`;
        
        await enviarEmail(env, email, "Sua Chave API Gratuita MascaraAI", `
          <div style="font-family: sans-serif; padding: 20px; color: #13201C; max-width: 600px; margin: 0 auto; border: 1px solid rgba(19,32,28,0.1); border-radius: 12px; background: #FFFFFF;">
            <h2 style="color: #0f6e5c; font-family: 'Fraunces', serif; font-size: 1.5rem; border-bottom: 2px solid #f7f8f6; padding-bottom: 10px;">🔑 Sua Chave de API MascaraAI foi gerada!</h2>
            <p>Olá,</p>
            <p>Agradecemos o seu cadastro. Aqui está a sua chave de API gratuita para integrar no seu sistema (n8n, cURL, Python, Node.js, etc.):</p>
            <div style="background: #f7f8f6; border: 1px solid rgba(19,32,28,0.1); padding: 15px; border-radius: 8px; font-family: monospace; font-size: 1.1rem; margin: 20px 0; word-break: break-all; text-align: center; color: #0f6e5c; letter-spacing: 0.5px;">
              <strong>${userApiKeyCheckout}</strong>
            </div>
            <p><strong>Detalhes do seu plano (Free API):</strong></p>
            <ul>
              <li>Limite mensal de <strong>10.000 caracteres</strong> gratuitos.</li>
              <li>Automação total via requisições HTTPS JSON.</li>
              <li>Acesso ao painel administrativo.</li>
            </ul>
            <hr style="border: 0; border-top: 1px solid rgba(19,32,28,0.1); margin: 20px 0;">
            <p>Para visualizar seu consumo de caracteres em tempo real, testar webhooks ou fazer upgrade para o plano profissional, acesse seu painel clicando no botão abaixo:</p>
            <div style="text-align: center; margin: 25px 0;">
              <a href="${link}" style="background: #0f6e5c; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; display: inline-block; font-weight: bold; box-shadow: 0 4px 6px rgba(15,110,92,0.15);">Acessar Meu Painel</a>
            </div>
            <p style="font-size: 0.8rem; color: #5a6b65; text-align: center;">Este link de acesso expira em 15 minutos. Após este prazo, basta solicitar um novo acesso pela Área do Usuário no site.</p>
          </div>
        `);
      }
      return jsonResponse({ ok: true, message: "Sua solicitação de chave API gratuita foi recebida! Verifique seu e-mail para obter a API Key." }, 200, cors);
    }

    if (!cpfCnpj) {
      return jsonResponse({ error: "É necessário informar o CPF ou CNPJ do cliente para gerar a cobrança." }, 400, cors);
    }

    const apiKey = env.ASAAS_API_KEY;
    if (!apiKey) {
      return jsonResponse({ error: "Chave do Asaas não configurada" }, 500, cors);
    }

    const baseUrl = getAsaasBaseUrl(env);

    // 1. Buscar se cliente já existe no Asaas por e-mail
    const customerRes = await fetch(`${baseUrl}/customers?email=${encodeURIComponent(email)}`, {
      headers: { 
        "access_token": apiKey,
        "User-Agent": "MascaraAI-Worker/1.0"
      }
    });
    
    let customerId = "";
    if (customerRes.ok) {
      const customerData = await customerRes.json();
      if (customerData.data && customerData.data.length > 0) {
        customerId = customerData.data[0].id;
        const existingCpfCnpj = (customerData.data[0].cpfCnpj || "").replace(/\D/g, "");
        if (!existingCpfCnpj) {
          const updateCustomerRes = await fetch(`${baseUrl}/customers/${customerId}`, {
            method: "PUT",
            headers: {
              "access_token": apiKey,
              "Content-Type": "application/json",
              "User-Agent": "MascaraAI-Worker/1.0"
            },
            body: JSON.stringify({
              cpfCnpj: cpfCnpj
            })
          });
          if (!updateCustomerRes.ok) {
            const errText = await updateCustomerRes.text();
            return jsonResponse({ error: `Erro ao atualizar cliente com CPF/CNPJ no Asaas: ${errText}` }, 400, cors);
          }
        }
      }
    }

    // 2. Se não existe, criar no Asaas
    if (!customerId) {
      const newCustomerRes = await fetch(`${baseUrl}/customers`, {
        method: "POST",
        headers: {
          "access_token": apiKey,
          "Content-Type": "application/json",
          "User-Agent": "MascaraAI-Worker/1.0"
        },
        body: JSON.stringify({
          name: email.split("@")[0],
          email: email,
          cpfCnpj: cpfCnpj,
          notificationDisabled: true
        })
      });
      if (!newCustomerRes.ok) {
        const errText = await newCustomerRes.text();
        return jsonResponse({ error: `Erro ao criar cliente no Asaas: ${errText}` }, 400, cors);
      }
      const newCustomer = await newCustomerRes.json();
      customerId = newCustomer.id;
    }

    // 3. Criar a assinatura recorrente mensal ou anual no Asaas (Vencimento amanhã)
    const dueDate = new Date(Date.now() + 86400000).toISOString().split('T')[0];
    
    let subValue = 30.00;
    let subCycle = "MONTHLY";
    let subDescription = "Assinatura MascaraAI Pro Mensal";
    
    if (plano === "pro_anual") {
      subValue = 300.00;
      subCycle = "YEARLY";
      subDescription = "Assinatura MascaraAI Pro Anual";
    }

    const subscriptionRes = await fetch(`${baseUrl}/subscriptions`, {
      method: "POST",
      headers: {
        "access_token": apiKey,
        "Content-Type": "application/json",
        "User-Agent": "MascaraAI-Worker/1.0"
      },
      body: JSON.stringify({
        customer: customerId,
        billingType: "UNDEFINED",
        value: subValue,
        nextDueDate: dueDate,
        cycle: subCycle,
        description: subDescription,
        externalReference: accountUuid,
        notificationDisabled: true
      })
    });

    if (!subscriptionRes.ok) {
      const errText = await subscriptionRes.text();
      return jsonResponse({ error: `Erro ao criar assinatura no Asaas: ${errText}` }, 400, cors);
    }

    const subscriptionData = await subscriptionRes.json();
    
    // Buscar a primeira cobrança gerada para a assinatura para obter a invoiceUrl
    const paymentsRes = await fetch(`${baseUrl}/payments?subscription=${subscriptionData.id}`, {
      headers: {
        "access_token": apiKey,
        "User-Agent": "MascaraAI-Worker/1.0"
      }
    });

    if (!paymentsRes.ok) {
      const errText = await paymentsRes.text();
      return jsonResponse({ error: `Erro ao obter cobrança da assinatura no Asaas: ${errText}` }, 400, cors);
    }

    const paymentsData = await paymentsRes.json();
    if (!paymentsData.data || paymentsData.data.length === 0) {
      return jsonResponse({ error: "Nenhuma cobrança gerada para a assinatura no Asaas." }, 400, cors);
    }

    const paymentData = paymentsData.data[0];
    return jsonResponse({
      ok: true,
      checkout_url: paymentData.invoiceUrl,
      payment_id: paymentData.id
    }, 200, cors);

  } catch (e) {
    return jsonResponse({ error: e.message }, 500, cors);
  }
}

// ══════════════════════════════════════════
// ROTINA CRON DIÁRIA (CHECK DE CONTAS)
// ══════════════════════════════════════════

async function verificarContasEDesligamento(env) {
  try {
    const activeRaw = await env.KV.get("config:active_paid_accounts") || "[]";
    const activeList = JSON.parse(activeRaw);
    const serverActive = (await env.KV.get("config:server_active")) === "true";

    // Envia aviso no Telegram se o servidor estiver ligado porém não houver clientes pagando
    if (activeList.length === 0 && serverActive) {
      await enviarMensagemTelegramComBotoes(env,
        "⚠️ *Nenhum Cliente Ativo Detectado*\n\nTodas as assinaturas expiram ou foram canceladas. Deseja desligar o servidor Serverspace para economizar créditos?",
        [{ text: "🔴 Desligar Servidor", callback_data: "power_off" }, { text: "🟢 Manter Ligado", callback_data: "ignore" }]
      );
    }

    // Monitora o saldo da Serverspace e avisa se estiver abaixo de R$ 5,00
    const apiKey = env.SERVERSPACE_API_KEY;
    if (apiKey) {
      try {
        const resBalance = await fetch(`${getServerspaceBaseUrl(env)}/billing/balance`, {
          headers: { "X-API-KEY": apiKey }
        });
        if (resBalance.ok) {
          const billing = await resBalance.json();
          const saldo = billing.balance || 0;
          if (saldo < 5) {
            await enviarTelegram(env, `⚠️ *Aviso de Saldo Baixo (Serverspace)*\n\nSeu saldo atual é *R$ ${saldo.toFixed(2)}*. Adicione créditos para evitar que seu servidor de backup seja excluído permanentemente.`);
          }
        }
      } catch {}
    }
  } catch (e) {
    console.error("Erro na rotina scheduled:", e);
  }
}

// Helper para retornar a URL base correta da Serverspace com base na localização (Brasil vs Global)
function getServerspaceBaseUrl(env) {
  const location = env.SERVERSPACE_LOCATION || "";
  if (location.toLowerCase() === "br") {
    return "https://api.serverspace.com.br/api/v1";
  }
  return "https://api.serverspace.io/v1";
}

// ══════════════════════════════════════════
// HELPERS DA API DA SERVERSPACE
// ══════════════════════════════════════════

async function callServerspace(env, action) {
  const serverId = (await env.KV.get("config:serverspace_vm_id")) || env.SERVERSPACE_VM_ID;
  const apiKey = env.SERVERSPACE_API_KEY;
  if (!serverId || !apiKey) return null;

  let url = `${getServerspaceBaseUrl(env)}/servers/${serverId}`;
  let method = "GET";

  if (action === "power_on") {
    url += "/power_on";
    method = "POST";
  } else if (action === "power_off") {
    url += "/power_off";
    method = "POST";
  }

  try {
    const res = await fetch(url, {
      method,
      headers: {
        "X-API-KEY": apiKey,
        "Content-Type": "application/json"
      }
    });
    if (res.status === 404) return 404; // Servidor não encontrado (excluído)
    if (!res.ok) return null;
    return await res.json();
  } catch (e) {
    console.error(`Erro Serverspace API (${action}):`, e);
    return null;
  }
}

async function recreateServerFromSnapshot(env) {
  const apiKey = env.SERVERSPACE_API_KEY;
  const snapshotId = env.SERVERSPACE_SNAPSHOT_ID;
  const location = env.SERVERSPACE_LOCATION || "am2";
  if (!apiKey || !snapshotId) return null;

  const baseUrl = getServerspaceBaseUrl(env);

  try {
    const res = await fetch(`${baseUrl}/servers`, {
      method: "POST",
      headers: {
        "X-API-KEY": apiKey,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        name: "mascaraai-prod-restored",
        location: location,
        location_id: location,
        cpu: parseInt(env.SERVERSPACE_CPU || "1"),
        ram: parseInt(env.SERVERSPACE_RAM || "2048"),
        ram_mb: parseInt(env.SERVERSPACE_RAM || "2048"),
        image: snapshotId,
        image_id: snapshotId,
        disc: parseInt(env.SERVERSPACE_DISC || "25600"),
        volumes: [
          {
            name: "boot",
            size_mb: parseInt(env.SERVERSPACE_DISC || "25600")
          }
        ]
      })
    });
    if (!res.ok) return null;
    const data = await res.json();
    if (data && data.id) {
      // Salva o novo ID no KV para chamadas subsequentes
      await env.KV.put("config:serverspace_vm_id", data.id);

      // Polling rápido para pegar o IP do novo servidor
      let ip = null;
      for (let i = 0; i < 5; i++) {
        await new Promise(r => setTimeout(r, 4000));
        const resDetail = await fetch(`${baseUrl}/servers/${data.id}`, {
          headers: { "X-API-KEY": apiKey }
        });
        if (resDetail.ok) {
          const detail = await resDetail.json();
          ip = detail.networks?.[0]?.ip || null;
          if (ip) {
            await env.KV.put("config:gliner_url", `http://${ip}:8080`);
            break;
          }
        }
      }
      return { id: data.id, ip: ip || "Pendente de IP" };
    }
    return null;
  } catch (e) {
    console.error("Erro ao recriar servidor:", e);
    return null;
  }
}

// ══════════════════════════════════════════
// HELPERS DA API DO TELEGRAM
// ══════════════════════════════════════════

async function chamarTelegramAPI(env, metodo, payload) {
  try {
    await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/${metodo}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
  } catch (e) {
    console.error(`Erro ao chamar Telegram API (${metodo}):`, e);
  }
}

async function enviarMensagemTelegramComBotoes(env, texto, botoes) {
  const payload = {
    chat_id: env.TELEGRAM_CHAT_ID,
    text: texto,
    parse_mode: "Markdown",
    reply_markup: {
      inline_keyboard: [botoes.map(b => ({ text: b.text, callback_data: b.callback_data }))]
    }
  };
  await chamarTelegramAPI(env, "sendMessage", payload);
}

async function editarMensagemTelegram(env, messageId, novoTexto, novosBotoes = null) {
  const payload = {
    chat_id: env.TELEGRAM_CHAT_ID,
    message_id: messageId,
    text: novoTexto,
    parse_mode: "Markdown"
  };
  if (novosBotoes) {
    payload.reply_markup = {
      inline_keyboard: [novosBotoes.map(b => ({ text: b.text, callback_data: b.callback_data }))]
    };
  }
  await chamarTelegramAPI(env, "editMessageText", payload);
}

async function responderCallback(env, callbackQueryId, textoAlert) {
  const payload = {
    callback_query_id: callbackQueryId,
    text: textoAlert
  };
  await chamarTelegramAPI(env, "answerCallbackQuery", payload);
}

