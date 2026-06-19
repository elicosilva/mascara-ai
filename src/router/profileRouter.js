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
