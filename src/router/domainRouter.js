// Domain Router: Roteador de domínio que seleciona as estratégias de perfil adequadas (Strategy Pattern)
import { ProfileRouter } from "./profileRouter.js";

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
