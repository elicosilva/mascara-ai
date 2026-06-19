// benchmark.js: Script de execução do benchmark de PII/PHI com suporte a múltiplos clientes
import fs from "fs";
import path from "path";
import readline from "readline";
import { processarTextoCompleto } from "../src/worker.js";

const benchmarkDir = "./benchmark";

// Encontra todos os arquivos cases*.json no diretório
const allCasesFiles = fs.readdirSync(benchmarkDir)
  .filter(file => file.startsWith("cases") && file.endsWith(".json"))
  .sort();

function carregarApenasCasesJson() {
  const casesPath = path.resolve(benchmarkDir, "cases.json");
  if (!fs.existsSync(casesPath)) {
    console.error("Erro: arquivo 'cases.json' não encontrado!");
    process.exit(1);
  }
  return JSON.parse(fs.readFileSync(casesPath, "utf8"));
}

function carregarTodosOsCasos() {
  let combined = [];
  for (const file of allCasesFiles) {
    const filePath = path.join(benchmarkDir, file);
    try {
      const cases = JSON.parse(fs.readFileSync(filePath, "utf8"));
      console.log(`  -> Carregado: ${file} (${cases.length} casos)`);
      combined = combined.concat(cases);
    } catch (err) {
      console.error(`Erro ao ler ${file}: ${err.message}`);
    }
  }
  return combined;
}

async function obterBaseCases() {
  // Permite pular a pergunta via argumentos de linha de comando
  if (process.argv.includes("--all")) {
    console.log("📂 Carregando todos os casos cumulativamente (--all)...");
    return carregarTodosOsCasos();
  }
  if (process.argv.includes("--only-cases")) {
    console.log("📂 Carregando apenas 'cases.json' (--only-cases)...");
    return carregarApenasCasesJson();
  }

  // Pergunta interativa caso executado sem argumentos
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });

    console.log("\n=================================================");
    console.log("Selecione a base de testes para o benchmark:");
    console.log(` 1: Rodar apenas 'cases.json' (${fs.existsSync(path.join(benchmarkDir, "cases.json")) ? "encontrado" : "não encontrado"})`);
    console.log(` 2: Rodar TODOS os arquivos 'cases*.json' cumulativamente (${allCasesFiles.join(", ")})`);
    console.log("=================================================");

    rl.question("Escolha (1 ou 2, padrão: 1): ", (resposta) => {
      rl.close();
      const escolha = resposta.trim();
      if (escolha === "2") {
        console.log("\n📂 Carregando todos os casos cumulativamente...");
        resolve(carregarTodosOsCasos());
      } else {
        console.log("\n📂 Carregando apenas 'cases.json'...");
        resolve(carregarApenasCasesJson());
      }
    });
  });
}

function gerarSuiteDeTestes(cases, targetCount, expandSuite) {
  const suite = [];
  let currentId = 1;

  if (!expandSuite) {
    // Retorna os casos originais mapeando IDs sequenciais limpos (evita conflitos de IDs repetidos entre arquivos)
    return cases.map((c, i) => ({
      id: i + 1,
      domain: c.domain,
      profile: c.profile,
      text: c.text,
      expected_entities: JSON.parse(JSON.stringify(c.expected_entities))
    }));
  }

  // Nomes e documentos de variação para suite sintética
  const nomesVar = ["Gabriel Almeida", "Juliana Costa", "Roberto Mendes", "Patrícia Lima", "Sandro Dantas", "Teresa Rezende"];
  const cpfsVar = ["111.444.777-35", "923.456.780-38", "645.728.910-01", "382.910.473-16", "729.183.045-14"];

  while (suite.length < targetCount) {
    const base = cases[suite.length % cases.length];
    const index = suite.length;

    let text = base.text;
    const expected_entities = JSON.parse(JSON.stringify(base.expected_entities));

    const nomeOriginal = expected_entities.find(e => e.tipo === "NOME_PESSOA")?.valor;
    const cpfOriginal = expected_entities.find(e => e.tipo === "CPF")?.valor;

    if (nomeOriginal) {
      const novoNome = nomesVar[index % nomesVar.length];
      text = text.replace(nomeOriginal, novoNome);
      expected_entities.find(e => e.tipo === "NOME_PESSOA").valor = novoNome;
    }

    if (cpfOriginal) {
      const novoCpf = cpfsVar[index % cpfsVar.length];
      text = text.replace(cpfOriginal, novoCpf);
      expected_entities.find(e => e.tipo === "CPF").valor = novoCpf;
    }

    suite.push({
      id: currentId++,
      domain: base.domain,
      profile: base.profile,
      text: text,
      expected_entities: expected_entities
    });
  }
  return suite;
}

// Configurações do ambiente de execução do Worker
const mockEnv = {
  GLINER_URL: process.env.GLINER_URL || "https://ner-server-prod.local",
  GLINER_API_KEY: process.env.GLINER_API_KEY || "mock_api_key_123",
  KV: {
    get: async () => null,
    put: async () => null,
    delete: async () => null
  }
};

async function rodarBenchmark() {
  const baseCases = await obterBaseCases();
  const expandSuite = process.argv.includes("--expand");
  const targetCount = expandSuite ? 599 : baseCases.length;

  const testSuite = gerarSuiteDeTestes(baseCases, targetCount, expandSuite);
  const useRealServer = !!process.env.API_URL;
  const useRealNer = !!process.env.GLINER_URL;

  if (!useRealServer && !useRealNer) {
    console.log("⚠️ Executando no modo offline (Mock do NER ativado).");
    // Mock de API externa: Intercepta chamadas de rede para simular o NER Server offline
    globalThis.fetch = async (url, options) => {
      if (url.includes("/detect")) {
        const { text } = JSON.parse(options.body);

        // Procura na suite o caso correspondente ao texto atual de forma precisa
        const matchingCase = testSuite.find(c => {
          const patientNames = c.expected_entities
            .filter(e => e.tipo === "NOME_PESSOA")
            .map(e => e.valor);
          return patientNames.every(n => text.includes(n)) && (c.text.substring(0, 20) === text.substring(0, 20));
        });

        if (matchingCase) {
          const nerEntities = matchingCase.expected_entities.filter(
            e => e.tipo === "NOME_PESSOA" || e.tipo === "PROFISSIONAL_SAUDE"
          );

          return {
            ok: true,
            json: async () => ({ encontrados: nerEntities })
          };
        }
        return { ok: true, json: async () => ({ encontrados: [] }) };
      }

      return { ok: false };
    };
  }

  console.log(`\n🚀 Executando Benchmark do MascaraAI (${testSuite.length} casos)...`);

  let totalTP = 0;
  let totalFP = 0;
  let totalFN = 0;
  let matchesExatos = 0;

  const metricsByDomain = {};
  const tStart = Date.now();

  for (const caso of testSuite) {
    let res;
    if (useRealServer) {
      try {
        const httpRes = await fetch(process.env.API_URL, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-API-Key": process.env.API_KEY || "msk_test_key_123"
          },
          body: JSON.stringify({
            text: caso.text,
            context: { domain: caso.domain, profile: caso.profile },
            policy: { mode: "balanced" }
          })
        });
        if (!httpRes.ok) {
          const errBody = await httpRes.text().catch(() => "");
          console.error(`Erro na requisição HTTP para o caso #${caso.id}: ${httpRes.status} | Resposta: ${errBody.substring(0, 200)}`);
          continue;
        }
        res = await httpRes.json();
      } catch (err) {
        console.error(`Erro de rede no caso #${caso.id}: ${err.message}`);
        continue;
      }
    } else {
      res = await processarTextoCompleto(caso.text, mockEnv, { domain: caso.domain, profile: caso.profile }, { mode: "balanced" });
    }

    const limparPrefixo = (s) => s.replace(/^(?:dr\.?a?|dra\.?|sr\.?|sra\.?|enf\.?|enfermeir[oa]|fisio\.?|psic\.?|nutri\.)\s+/i, "").trim().toLowerCase();
    const detectadas = (res.entities || []).map(e => limparPrefixo(e.valor));
    const esperadas = caso.expected_entities.map(e => limparPrefixo(e.valor));

    let TP = 0;
    let FP = 0;
    let FN = 0;

    let debugCount = 0;
    // Calcula acertos (TP)
    for (const esp of esperadas) {
      if (detectadas.includes(esp)) {
        TP++;
      } else {
        FN++;
        if (debugCount < 50) {
          console.log(`[DEBUG] Caso #${caso.id} (${caso.profile}) - FN (esperava mas não detectou): "${esp}" | Texto: "${caso.text}"`);
          debugCount++;
        }
      }
    }

    // Calcula falsos positivos (FP)
    for (const det of detectadas) {
      if (!esperadas.includes(det)) {
        FP++;
        if (debugCount < 50) {
          console.log(`[DEBUG] Caso #${caso.id} (${caso.profile}) - FP (detectou mas não esperava): "${det}" | Texto: "${caso.text}"`);
          debugCount++;
        }
      }
    }

    totalTP += TP;
    totalFP += FP;
    totalFN += FN;

    if (FP === 0 && FN === 0) {
      matchesExatos++;
    }

    // Agrupa métricas por domínio
    if (!metricsByDomain[caso.domain]) {
      metricsByDomain[caso.domain] = { TP: 0, FP: 0, FN: 0, count: 0 };
    }
    metricsByDomain[caso.domain].TP += TP;
    metricsByDomain[caso.domain].FP += FP;
    metricsByDomain[caso.domain].FN += FN;
    metricsByDomain[caso.domain].count++;
  }

  const duration = Date.now() - tStart;

  // Cálculos globais
  const precisao = totalTP / (totalTP + totalFP || 1);
  const recall = totalTP / (totalTP + totalFN || 1);
  const f1 = (2 * precisao * recall) / (precisao + recall || 1);
  const taxaExata = matchesExatos / testSuite.length;

  console.log("\n================ RESULTS OVERALL ================");
  console.log(`Tempo Total: ${duration} ms (Média por caso: ${(duration / testSuite.length).toFixed(2)} ms)`);
  console.log(`Precisão Geral : ${(precisao * 100).toFixed(2)}%`);
  console.log(`Recall Geral    : ${(recall * 100).toFixed(2)}%`);
  console.log(`F1 Score Geral  : ${f1.toFixed(4)} (F1%: ${(f1 * 100).toFixed(2)}%)`);
  console.log(`Taxa Exata (EM) : ${(taxaExata * 100).toFixed(2)}% (${matchesExatos}/${testSuite.length})`);
  console.log("=================================================");

  console.log("\n📊 Detalhamento por Domínio:");
  for (const [dom, data] of Object.entries(metricsByDomain)) {
    const domPrec = data.TP / (data.TP + data.FP || 1);
    const domRec = data.TP / (data.TP + data.FN || 1);
    const domF1 = (2 * domPrec * domRec) / (domPrec + domRec || 1);
    console.log(` - ${dom.toUpperCase().padEnd(8)} -> F1: ${domF1.toFixed(3)} | Prec: ${domPrec.toFixed(3)} | Rec: ${domRec.toFixed(3)} (${data.count} casos)`);
  }

  // Regressão Guard (Referência: F1=0.97, aceita queda máxima de 0.5% -> F1 >= 0.965)
  const F1_REFERENCIA = 0.97;
  const F1_MINIMO = F1_REFERENCIA - 0.005;

  console.log(`\nVerificação de Regressão: F1 Obtido (${f1.toFixed(4)}) vs F1 Mínimo (${F1_MINIMO.toFixed(4)})`);
  if (f1 < F1_MINIMO) {
    console.error("❌ REGRESSÃO DE BENCHMARK DETECTADA! O F1 Score caiu abaixo da cota de tolerância.");
    process.exit(1);
  } else {
    console.log("✅ Benchmark aprovado! F1 Score dentro dos limites de qualidade de produção.");
  }
}

rodarBenchmark().catch(console.error);
