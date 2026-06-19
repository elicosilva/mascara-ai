// benchmark_local.js — Benchmark MascaraAI local (sem servidor HTTP)
// Roda diretamente a lógica de detecção para medir F1/Precision/Recall
import fs from "fs";
import path from "path";

import { InputAdapter } from "../src/adapters/inputAdapter.js";
import { ContextResolver } from "../src/resolvers/contextResolver.js";
import { DomainRouter } from "../src/router/domainRouter.js";
import { DetectionPipeline } from "../src/pipelines/detectionPipeline.js";
import { PromotionLayer } from "../src/layers/promotionLayer.js";
import { PolicyLayer } from "../src/layers/policyLayer.js";
import { MetricsTracker } from "../src/utils/metrics.js";

// Mock fetch para NER (retorna vazio — benchmark local sem NER)
globalThis.fetch = async () => ({ ok: false });

const benchmarkDir = "./benchmark";

// ══════════════════════════════════════════
// CARREGAMENTO DE CASOS
// ══════════════════════════════════════════
const allCasesFiles = fs.readdirSync(benchmarkDir)
  .filter(file => file.startsWith("cases") && file.endsWith(".json"))
  .sort();

function carregarApenasCasesJson() {
  const casesPath = path.resolve(benchmarkDir, "cases.json");
  return JSON.parse(fs.readFileSync(casesPath, "utf8"));
}

function carregarTodosOsCasos() {
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

// ══════════════════════════════════════════
// DETECÇÃO LOCAL (sem HTTP)
// ══════════════════════════════════════════
async function detectarLocal(texto) {
  const metrics = new MetricsTracker();
  const parsed = InputAdapter.parse({ text: texto });
  const resolvedCtx = ContextResolver.resolve(parsed.text, parsed.context);
  const strategy = DomainRouter.getStrategy(resolvedCtx.domain, resolvedCtx.profile);
  
  const env = { GLINER_URL: null };
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

// ══════════════════════════════════════════
// MAIN
// ══════════════════════════════════════════
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

  console.log(`🚀 Executando Benchmark Local (${baseCases.length} casos, sem NER)\n`);

  const tStart = Date.now();
  const resultados = [];
  const falhas = [];
  const errosPorCategoria = {};
  const fpPorTipoGlobal = {};
  const fnPorTipoGlobal = {};

  for (let i = 0; i < baseCases.length; i++) {
    const c = baseCases[i];
    const entrada = c.text || "";
    const esperado = [...new Set((c.expected_entities || []).map(e => e.tipo))];
    const categoria = `${c.domain || "auto"}/${c.profile || "generic"}`;

    try {
      const resultado = await detectarLocal(entrada);
      const detectados = [...new Set(resultado.deteccoes.map(d => d.tipo))];
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

    if ((i + 1) % 100 === 0) {
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

  // Erros por domínio
  const errosPorDominio = {};
  for (const [cat, count] of Object.entries(errosPorCategoria)) {
    const dominio = cat.split("/")[0];
    errosPorDominio[dominio] = (errosPorDominio[dominio] || 0) + count;
  }

  if (Object.keys(errosPorDominio).length > 0) {
    console.log("\n📊 ERROS POR DOMÍNIO:");
    for (const [dom, count] of Object.entries(errosPorDominio).sort((a, b) => b[1] - a[1])) {
      console.log(`  ${dom.toUpperCase().padEnd(15)} ${count} erros`);
    }
  }

  if (Object.keys(errosPorCategoria).length > 0) {
    console.log("\n📋 ERROS POR SUBCATEGORIA:");
    for (const [cat, count] of Object.entries(errosPorCategoria).sort((a, b) => b[1] - a[1])) {
      console.log(`  ${cat.padEnd(35)} ${count} erros`);
    }
  }

  if (Object.keys(fpPorTipoGlobal).length > 0) {
    console.log("\n⚠️  FALSOS POSITIVOS POR TIPO:");
    for (const [tipo, count] of Object.entries(fpPorTipoGlobal).sort((a, b) => b[1] - a[1])) {
      console.log(`  ${tipo.padEnd(24)} ${count}`);
    }
  }

  if (Object.keys(fnPorTipoGlobal).length > 0) {
    console.log("\n❌ FALSOS NEGATIVOS POR TIPO:");
    for (const [tipo, count] of Object.entries(fnPorTipoGlobal).sort((a, b) => b[1] - a[1])) {
      console.log(`  ${tipo.padEnd(24)} ${count}`);
    }
  }

  // Top falhas detalhadas
  if (falhas.length > 0) {
    console.log("\n🔍 DETALHES DAS FALHAS (top 20):");
    console.log("═".repeat(100));
    for (const f of falhas.slice(0, 20)) {
      console.log(`\n  #${f.id} [${f.categoria}]`);
      console.log(`  Texto: "${f.entrada.substring(0, 100)}${f.entrada.length > 100 ? '...' : ''}"`);
      console.log(`  Esperado : [${f.esperado.join(", ")}]`);
      console.log(`  Detectado: [${f.detectados.join(", ")}]`);
      if (f.fp_tipos.length) console.log(`  FP: ${f.fp_tipos.join(", ")}`);
      if (f.fn_tipos.length) console.log(`  FN: ${f.fn_tipos.join(", ")}`);
    }
  }

  console.log(`\n🔒 F1 obtido: ${f1.toFixed(4)} | Meta: 1.0000`);
  if (f1 >= 0.99) {
    console.log("✅ Benchmark EXCELENTE!");
  } else if (f1 >= 0.95) {
    console.log("🟡 Benchmark BOM, mas pode melhorar.");
  } else {
    console.log("🔴 Benchmark PRECISA de ajustes.");
  }
}

main().catch(err => {
  console.error("❌ Erro fatal:", err);
  process.exit(1);
});
