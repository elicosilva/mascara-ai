// pipeline.test.js: Testes unitários para validação das camadas do pipeline MascaraAI
import test from "node:test";
import assert from "node:assert";
import { InputAdapter } from "../src/adapters/inputAdapter.js";
import { ContextResolver } from "../src/resolvers/contextResolver.js";
import { MaskEngine } from "../src/engines/maskEngine.js";
import { DomainRouter } from "../src/router/domainRouter.js";
import worker, { processarTextoCompleto } from "../src/worker.js";

// Mock do ambiente KV e NER para testes unitários
const mockEnv = {
  GLINER_URL: "https://ner-prod.local",
  GLINER_API_KEY: "testkey123",
  KV: {
    get: async () => null,
    put: async () => null,
    delete: async () => null
  }
};

// Mock global do fetch para responder a chamadas NER
globalThis.fetch = async (url) => {
  if (url.includes("/detect")) {
    return {
      ok: true,
      json: async () => ({
        encontrados: [
          { tipo: "NOME_PESSOA", valor: "Fernando Mendes" }
        ]
      })
    };
  }
  return { ok: false };
};

test("1. Input Adapter - Deve extrair texto corretamente de diferentes payloads", () => {
  // Caso A: Texto plano
  const resA = InputAdapter.parse("Olá Mundo");
  assert.strictEqual(resA.text, "Olá Mundo");

  // Caso B: JSON com payload.mensagem
  const resB = InputAdapter.parse({
    payload: { mensagem: "Mensagem do WhatsApp" },
    context: { domain: "chat" }
  });
  assert.strictEqual(resB.text, "Mensagem do WhatsApp");
  assert.strictEqual(resB.context.domain, "chat");

  // Caso C: JSON com text padrão
  const resC = InputAdapter.parse({
    text: "Texto padrão do JSON",
    policy: { mode: "strict" }
  });
  assert.strictEqual(resC.text, "Texto padrão do JSON");
  assert.strictEqual(resC.policy.mode, "strict");

  // Caso D: Fallback de serialização de corpo
  const resD = InputAdapter.parse({
    chaveQualquer: "valorQualquer",
    numero: 42
  });
  assert.ok(resD.text.includes("chaveQualquer"));
  assert.ok(resD.text.includes("valorQualquer"));
});

test("2. Context Resolver - Deve mapear heurísticas de termos para domínios/perfis", () => {
  // Caso A: Termos neurológicos
  const resA = ContextResolver.resolve("Paciente neurológico estável.");
  assert.strictEqual(resA.domain, "health");
  assert.strictEqual(resA.profile, "uti_evolucao");

  // Caso B: Triagem enfermagem
  const resB = ContextResolver.resolve("Paciente desperta às 06h. FC 72, PA 110.");
  assert.strictEqual(resB.domain, "health");
  assert.strictEqual(resB.profile, "uti_enfermagem");

  // Caso C: Log do sistema
  const resC = ContextResolver.resolve("Aconteceu um erro no request_id trace.");
  assert.strictEqual(resC.domain, "logs");
  assert.strictEqual(resC.profile, "application_log");

  // Caso D: Fallback para termos desconhecidos
  const resD = ContextResolver.resolve("Texto genérico qualquer.");
  assert.strictEqual(resD.domain, "auto");
  assert.strictEqual(resD.profile, "generic");
});

test("3. Strategy Router - Deve selecionar a estratégia correta", () => {
  const strategy = DomainRouter.getStrategy("health", "uti_enfermagem");
  assert.strictEqual(strategy.name, "UTI_ENFERMAGEM");
  assert.strictEqual(strategy.regexMode, "dominant");
  assert.strictEqual(strategy.nerMode, "minimal");
});

test("4. Mask Engine - Deve proteger chaves JSON durante o mascaramento", () => {
  const jsonText = '{"nome": "Fernando Mendes", "cpf": "123.456.789-00"}';
  
  // Nomes de chaves ("nome", "cpf") não devem ser mascarados, apenas seus valores
  const detections = [
    { tipo: "NOME_PESSOA", valor: "Fernando Mendes", token: "⟦PII:NOME:1234⟧" },
    { tipo: "CPF", valor: "123.456.789-00", token: "⟦PII:CPF:5678⟧" }
  ];
  
  const strategy = { sanitizeChunk: false };
  const masked = MaskEngine.mask(jsonText, detections, strategy);
  
  // As chaves se mantêm intactas
  assert.ok(masked.includes('"nome":'));
  assert.ok(masked.includes('"cpf":'));
  // Os valores foram substituídos
  assert.ok(masked.includes("⟦PII:NOME:1234⟧"));
  assert.ok(masked.includes("⟦PII:CPF:5678⟧"));
});

test("5. End-to-End Pipeline - Processamento completo de dados clínicos", async () => {
  const textoClinico = "Subjetivo: Paciente Fernando Mendes com CPF 111.444.777-35 apresenta boa evolução.";
  
  const res = await processarTextoCompleto(
    textoClinico, 
    mockEnv, 
    { domain: "health", profile: "uti_evolucao" }, 
    { mode: "balanced" }
  );

  // Valida saídas estruturadas
  assert.ok(res.masked_text.includes("⟦PII:NOME_PESSOA:"));
  assert.ok(res.masked_text.includes("⟦PII:CPF:"));
  assert.strictEqual(res.context_detected.domain, "health");
  assert.strictEqual(res.context_detected.profile, "uti_evolucao");
  
  // Valida o Classification Report
  assert.ok(res.classification_report.masked_categories.includes("CPF"));
  assert.ok(res.classification_report.risk_score > 0);
  
  // Valida as métricas
  assert.ok(res.metrics.tempo_ms >= 0);
  assert.ok(res.metrics.regex_ms >= 0);
  assert.ok(res.metrics.ner_ms >= 0);
});

test("6. Stateless Auth Flow - Deve emitir e validar tokens sem erro", async () => {
  const env = {
    JWT_SECRET: "test_secret_key_123",
    KV: {
      get: async () => null,
      put: async () => null,
      delete: async () => null
    },
    RESEND_API_KEY: "re_mock_key" // Força o envio de e-mail mockado
  };

  // 1. Solicitar link de acesso
  const reqSol = new Request("https://mascaraai.com/api/sessao/solicitar", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: "eli.c16silva@gmail.com" })
  });
  
  // Interceptamos o envio de e-mail mockado
  let sentLink = "";
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    if (url.includes("resend.com") || url.includes("sendgrid.com")) {
      const body = JSON.parse(options.body);
      const match = body.html.match(/href="([^"]+)"/);
      if (match) sentLink = match[1];
      return { ok: true };
    }
    return originalFetch(url, options);
  };

  const resSol = await worker.fetch(reqSol, env);
  assert.strictEqual(resSol.status, 200);
  const dataSol = await resSol.json();
  assert.ok(dataSol.ok);

  // Restaura o fetch global
  globalThis.fetch = originalFetch;

  // Extrai o token do link gerado
  assert.ok(sentLink.includes("token="));
  const token = new URL(sentLink).searchParams.get("token");

  // 2. Confirmar token para obter session_token
  const reqConf = new Request("https://mascaraai.com/api/sessao/confirmar", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token })
  });

  const resConf = await worker.fetch(reqConf, env);
  assert.strictEqual(resConf.status, 200);
  const dataConf = await resConf.json();
  assert.ok(dataConf.ok);
  assert.ok(dataConf.session_token);
  assert.strictEqual(dataConf.email, "eli.c16silva@gmail.com");

  // 3. Acessar conta com o session_token stateless
  const reqAcc = new Request("https://mascaraai.com/api/account", {
    method: "GET",
    headers: { "X-Session-Token": dataConf.session_token }
  });

  const resAcc = await worker.fetch(reqAcc, env);
  assert.strictEqual(resAcc.status, 200);
  const dataAcc = await resAcc.json();
  assert.strictEqual(dataAcc.email, "eli.c16silva@gmail.com");
  assert.strictEqual(dataAcc.plano, "free"); // fallback padrão
});

test("7. Developer Mode Bypass - Deve permitir acesso instantâneo com token de bypass sob falha de KV", async () => {
  const env = {
    DEV_MODE: "true",
    KV: {
      get: async () => { throw new Error("KV_EXHAUSTED"); } // Simulando KV completamente quebrado/bloqueado
    }
  };

  const reqAcc = new Request("https://mascaraai.com/api/account", {
    method: "GET",
    headers: { "X-Session-Token": "dev_session_token" }
  });

  const resAcc = await worker.fetch(reqAcc, env);
  assert.strictEqual(resAcc.status, 200);
  const dataAcc = await resAcc.json();
  assert.strictEqual(dataAcc.email, "eli.c16silva@gmail.com");
  assert.strictEqual(dataAcc.plano, "enterprise"); // fallback padrão de desenvolvedor sem quebrar a requisição
});

test("8. Anomaly Detection - Não deve apontar como anomalia termos que foram mascarados", async () => {
  const text = "O paciente Fernando Mendes com CPF 923.456.780-38 e telefone (11) 98888-7777 foi atendido no Hospital de São Paulo. Outro numero suspeito nao catalogado e 987654.";
  
  const res = await processarTextoCompleto(
    text, 
    mockEnv, 
    { domain: "health", profile: "uti_evolucao" }, 
    { mode: "balanced" }
  );

  const suspects = res.classification_report.suspected_unmasked_items;
  
  // Termos que foram mascarados ("Fernando", "Mendes", "923.456.780-38", "(11) 98888-7777") não devem estar na lista de suspeitos
  assert.ok(!suspects.includes("Fernando"), "Fernando não deve ser apontado como anomalia pois foi mascarado");
  assert.ok(!suspects.includes("Mendes"), "Mendes não deve ser apontado como anomalia pois foi mascarado");
  assert.ok(!suspects.includes("98888"), "O telefone mascarado não deve ser apontado como anomalia");
  assert.ok(!suspects.includes("7777"), "O telefone mascarado não deve ser apontado como anomalia");

  // Mas termos não mascarados válidos devem ser apontados
  assert.ok(suspects.includes("Hospital"), "Hospital deve ser apontado como suspeito não catalogado");
  assert.ok(suspects.includes("São") || suspects.includes("Paulo"), "Nomes geográficos/institucionais não catalogados devem ser apontados");
  assert.ok(suspects.includes("987654"), "Número não mascarado 987654 deve ser apontado como anomalia");

  // CPF formatado (mesmo matematicamente inválido como 240.237.490-26) deve ser mascarado para evitar vazamento
  const textWithInvalidCpf = "Paciente com CPF: 240.237.490-26.";
  const res2 = await processarTextoCompleto(
    textWithInvalidCpf,
    mockEnv,
    { domain: "health", profile: "uti_evolucao" },
    { mode: "balanced" }
  );
  assert.ok(res2.masked_text.includes("⟦PII:CPF:"), "CPF formatado deve ser mascarado");

  // Documento PIS matematicamente inválido (como 120.45678.90-1) que falhou no pipeline de mascaramento deve ser detectado como anomalia/suspeita
  const textWithInvalidPis = "Paciente com PIS invalido: 120.45678.90-1.";
  const res3 = await processarTextoCompleto(
    textWithInvalidPis,
    mockEnv,
    { domain: "health", profile: "uti_evolucao" },
    { mode: "balanced" }
  );
  assert.ok(res3.classification_report.suspected_unmasked_items.includes("120.45678.90-1"), "PIS inválido formatado deve ser exposto como suspeita/anomalia");

  // Verifica se ignore_list customizada na policy remove termos da lista de anomalias
  const textWithIgnore = "Paciente com CPF: 240.237.490-26. Exemplo Hospital Clinico.";
  const res4 = await processarTextoCompleto(
    textWithIgnore,
    mockEnv,
    { domain: "health", profile: "uti_evolucao" },
    { mode: "balanced", ignore_list: ["Hospital", "Clinico"] }
  );
  const suspects4 = res4.classification_report.suspected_unmasked_items;
  assert.ok(!suspects4.includes("Hospital"), "Hospital deve ser ignorado de acordo com a ignore_list");
  assert.ok(!suspects4.includes("Clinico"), "Clinico deve ser ignorado de acordo com a ignore_list");
  assert.ok(!suspects4.includes("240.237.490-26"), "CPF inválido foi mascarado, logo não deve ser exposto como suspeita unmasked");
});

test("9. Plan Limits and Custom Cotas - Deve processar cota base e converter tipo string de forma segura", async () => {
  const env = {
    JWT_SECRET: "test_secret_key_123",
    KV: {
      get: async (key) => {
        if (key === "session:test_session_token") {
          return JSON.stringify({ email: "test@example.com", account_uuid: "test_uuid", role: "owner" });
        }
        if (key === "account:test_uuid") {
          // Simulando o bug onde chars_mes_custom está salvo como string "0" e plano é "pro"
          return JSON.stringify({
            uuid: "test_uuid",
            email: "test@example.com",
            plano: "pro",
            chars_mes_custom: "0",
            uso_mes: 0,
            webhook_url: ""
          });
        }
        if (key === "member:test@example.com") {
          return JSON.stringify({ account_uuid: "test_uuid", role: "owner", api_key: "test_api_key", limite_dia: 0 });
        }
        return null;
      },
      put: async () => null,
      delete: async () => null
    }
  };

  const req = new Request("https://mascaraai.com/api/account", {
    method: "GET",
    headers: { "X-Session-Token": "test_session_token" }
  });

  const res = await worker.fetch(req, env);
  assert.strictEqual(res.status, 200);
  const data = await res.json();
  
  // A cota deve cair de volta para o padrão de Pro (10.000.000) ao invés de usar string "0" ou valor 0
  assert.strictEqual(data.chars_mes, 10000000);
  assert.strictEqual(data.plano, "pro");
});
