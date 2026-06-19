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
