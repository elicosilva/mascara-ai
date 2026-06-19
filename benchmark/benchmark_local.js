// benchmark_local.js — Benchmark MascaraAI local (sem servidor HTTP por padrão, mas compatível com NER se ativo)
import fs from "fs";
import path from "path";

import { InputAdapter } from "../src/adapters/inputAdapter.js";
import { ContextResolver } from "../src/resolvers/contextResolver.js";
import { DomainRouter } from "../src/router/domainRouter.js";
import { DetectionPipeline } from "../src/pipelines/detectionPipeline.js";
import { PromotionLayer } from "../src/layers/promotionLayer.js";
import { PolicyLayer } from "../src/layers/policyLayer.js";
import { MetricsTracker } from "../src/utils/metrics.js";

// Configurações do Servidor NER de teste
const USE_NER = process.argv.includes("--use-ner");
const NER_URL = process.env.GLINER_URL || "http://localhost:8080";

if (!USE_NER) {
  console.log("ℹ️  NER desativado por padrão no modo local (use '--use-ner' para testar com o BERT ativo)");
  globalThis.fetch = async () => ({ ok: false });
} else {
  console.log(`📡 Conectando ao NER Server em: ${NER_URL}`);
  // Mantém a função nativa do fetch para bater no uvicorn localhost
}

const benchmarkDir = "./benchmark";

// Mapeamento de taxonomia do MascaraAI para o AnonyMED-BR
const TRANSLATE_MAP = {
  // MascaraAI -> AnonyMED-BR
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

function traduzirTipo(tipo) {
  return TRANSLATE_MAP[tipo] || tipo;
}

function carregarApenasCasesJson() {
  const casesPath = path.resolve(benchmarkDir, "cases.json");
  return JSON.parse(fs.readFileSync(casesPath, "utf8"));
}

function carregarTodosOsCasos() {
  const allCasesFiles = fs.readdirSync(benchmarkDir)
    .filter(file => file.startsWith("cases") && file.endsWith(".json"))
    .sort();

  let combined = [];
  for (const file of allCasesFiles) {
    const filePath = path.join(benchmarkDir, file);
    try {
      const cases = JSON.parse(fs.readFileSync(filePath, "utf8"));
      console.log(`  → Carregado: ${file} (${cases.length} casos)`);
      combined = combined.concat(cases);
    } catch (err) {
      console.error(`  ❌ Erro ao ler ${file}: ${err.message}`);
    }
  }
  return combined;
}

async function detectarLocal(texto) {
  const metrics = new MetricsTracker();
  
  // Limpa as tags XML sintéticas do dataset antes de processar
  const cleanText = texto.replace(/<[A-Z_]+>|<\/[A-Z_]+\/>/g, "");
  
  const parsed = InputAdapter.parse({ text: cleanText });
  // Força o profile clínico para o dataset AnonyMED-BR
  parsed.context = { domain: "health", profile: "clinical" };
  
  const resolvedCtx = ContextResolver.resolve(parsed.text, parsed.context);
  const strategy = DomainRouter.getStrategy(resolvedCtx.domain, resolvedCtx.profile);
  
  const env = { GLINER_URL: USE_NER ? NER_URL : null };
  const detectionResult = await DetectionPipeline.run(parsed.text, env, strategy, metrics);
  
  const allDetections = [...detectionResult.regexDetections, ...detectionResult.nerDetections];
  const promotedDetections = await PromotionLayer.promote(allDetections, parsed.text, strategy);
  
  const policyResult = await PolicyLayer.apply(
    parsed.text,
    promotedDetections,
    [],
    strategy,
    {}
  );

  return {
    deteccoes: policyResult.detections,
    resolvedCtx
  };
}

async function main() {
  const useAll = process.argv.includes("--all");
  let baseCases;

  if (useAll) {
    console.log("📂 Carregando todos os casos (--all)...\n");
    baseCases = carregarTodosOsCasos();
  } else {
    console.log("📂 Carregando apenas 'cases.json'...\n");
    baseCases = carregarApenasCasesJson();
  }

  console.log(`🚀 Executando Benchmark Local (${baseCases.length} casos)\n`);

  const tStart = Date.now();
  const resultados = [];
  const falhas = [];
  const errosPorCategoria = {};
  const fpPorTipoGlobal = {};
  const fnPorTipoGlobal = {};

  for (let i = 0; i < baseCases.length; i++) {
    const c = baseCases[i];
    const entrada = c.text || "";
    // O benchmark espera subcategory ou category das labels anotadas
    const esperado = [...new Set((c.labels || []).map(e => e.subcategory || e.category))];
    const categoria = `${c.domain || "auto"}/${c.profile || "generic"}`;

    try {
      const resultado = await detectarLocal(entrada);
      
      // Traduz os tipos identificados no MascaraAI para o padrão do AnonyMED-BR antes de calcular as métricas
      const detectados = [...new Set(resultado.deteccoes.map(d => traduzirTipo(d.tipo)))];
      
      const tp = detectados.filter(t => esperado.includes(t)).length;
      const fp = detectados.filter(t => !esperado.includes(t)).length;
      const fn = esperado.filter(t => !detectados.includes(t)).length;
      const ok = fp === 0 && fn === 0;

      resultados.push({ tp, fp, fn });
      if (!ok) {
        falhas.push({
          id: c.id || i + 1, categoria, entrada,
          esperado, detectados,
          fp_tipos: detectados.filter(t => !esperado.includes(t)),
          fn_tipos: esperado.filter(t => !detectados.includes(t)),
        });
        errosPorCategoria[categoria] = (errosPorCategoria[categoria] || 0) + 1;
        for (const t of detectados.filter(t => !esperado.includes(t))) {
          fpPorTipoGlobal[t] = (fpPorTipoGlobal[t] || 0) + 1;
        }
        for (const t of esperado.filter(t => !detectados.includes(t))) {
          fnPorTipoGlobal[t] = (fnPorTipoGlobal[t] || 0) + 1;
        }
      }
    } catch (err) {
      console.error(`  ❌ Erro caso ${c.id || i + 1}: ${err.message}`);
    }

    if ((i + 1) % 50 === 0) {
      process.stdout.write(`  Processados ${i + 1}/${baseCases.length}...\r`);
    }
  }

  const duration = Date.now() - tStart;

  // ══════════════════════════════════════════
  // AGREGAÇÃO
  // ══════════════════════════════════════════
  const totalTP = resultados.reduce((s, r) => s + r.tp, 0);
  const totalFP = resultados.reduce((s, r) => s + r.fp, 0);
  const totalFN = resultados.reduce((s, r) => s + r.fn, 0);
  const precision = totalTP / (totalTP + totalFP) || 0;
  const recall    = totalTP / (totalTP + totalFN) || 0;
  const f1        = 2 * precision * recall / (precision + recall) || 0;

  // ══════════════════════════════════════════
  // RELATÓRIO
  // ══════════════════════════════════════════
  console.log("\n\n════════════════ RESULTS OVERALL ════════════════");
  console.log(`Tempo Total     : ${duration} ms (${(duration/1000).toFixed(1)}s)`);
  console.log(`Total de Casos  : ${baseCases.length}`);
  console.log(`Acertos Exatos  : ${baseCases.length - falhas.length} (${(((baseCases.length - falhas.length) / baseCases.length) * 100).toFixed(2)}%)`);
  console.log(`Falhas          : ${falhas.length}`);
  console.log(`Precisão Geral  : ${(precision * 100).toFixed(2)}%`);
  console.log(`Recall Geral    : ${(recall * 100).toFixed(2)}%`);
  console.log(`F1 Score Geral  : ${f1.toFixed(4)} (${(f1 * 100).toFixed(2)}%)`);
  console.log("══════════════════════════════════════════════════");

  if (Object.keys(errosPorCategoria).length > 0) {
    console.log("\n📋 ERROS POR SUBCATEGORIA DE BENCHMARK:");
    for (const [cat, count] of Object.entries(errosPorCategoria).sort((a, b) => b[1] - a[1])) {
      console.log(`  ${cat.padEnd(35)} ${count} erros`);
    }
  }

  if (Object.keys(fpPorTipoGlobal).length > 0) {
    console.log("\n⚠️  FALSOS POSITIVOS POR TIPO (TRADUZIDOS):");
    for (const [tipo, count] of Object.entries(fpPorTipoGlobal).sort((a, b) => b[1] - a[1])) {
      console.log(`  ${tipo.padEnd(24)} ${count}`);
    }
  }

  if (Object.keys(fnPorTipoGlobal).length > 0) {
    console.log("\n❌ FALSOS NEGATIVOS POR TIPO (TRADUZIDOS):");
    for (const [tipo, count] of Object.entries(fnPorTipoGlobal).sort((a, b) => b[1] - a[1])) {
      console.log(`  ${tipo.padEnd(24)} ${count}`);
    }
  }

  console.log(`\n🔒 F1 obtido: ${f1.toFixed(4)}`);
}

main().catch(err => {
  console.error("❌ Erro fatal:", err);
  process.exit(1);
});
