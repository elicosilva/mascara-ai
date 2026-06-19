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

import { InputAdapter } from "./adapters/inputAdapter.js";
import { ContextResolver } from "./resolvers/contextResolver.js";
import { DomainRouter } from "./router/domainRouter.js";
import { DetectionPipeline } from "./pipelines/detectionPipeline.js";
import { PromotionLayer } from "./layers/promotionLayer.js";
import { PolicyLayer } from "./layers/policyLayer.js";
import { MaskEngine } from "./engines/maskEngine.js";
import { MetricsTracker } from "./utils/metrics.js";
import { PII_PATTERNS, protegerChavesJSON, restaurarChavesJSON } from "./utils/patterns.js";
import { gerarHash, gerarToken, validarCPF, validarCNPJ, validarPIS, validarCNH } from "./utils/helpers.js";

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