// benchmark.js — Benchmark MascaraAI via endpoint /api/benchmark do Worker
// Versão com relatório completo por categoria/subcategoria
import fs from "fs";
import path from "path";
import readline from "readline";

const benchmarkDir = "./benchmark";
const WORKER_URL = process.env.WORKER_URL || "http://localhost:8787";
const ADMIN_SECRET = process.env.ADMIN_SECRET || "";
const LOTE_TAMANHO = parseInt(process.env.LOTE || "50");

// ══════════════════════════════════════════
// CARREGAMENTO DE CASOS
// ══════════════════════════════════════════
const allCasesFiles = fs.readdirSync(benchmarkDir)
  .filter(file => file.startsWith("cases") && file.endsWith(".json"))
  .sort();

function carregarApenasCasesJson() {
  const casesPath = path.resolve(benchmarkDir, "cases.json");
  if (!fs.existsSync(casesPath)) {
    console.error("❌ Erro: arquivo 'cases.json' não encontrado!");
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
      console.log(`  → Carregado: ${file} (${cases.length} casos)`);
      combined = combined.concat(cases);
    } catch (err) {
      console.error(`  ❌ Erro ao ler ${file}: ${err.message}`);
    }
  }
  return combined;
}

async function obterBaseCases() {
  if (process.argv.includes("--all")) {
    console.log("📂 Carregando todos os casos cumulativamente (--all)...\n");
    return carregarTodosOsCasos();
  }
  if (process.argv.includes("--only-cases")) {
    console.log("📂 Carregando apenas 'cases.json' (--only-cases)...\n");
    return carregarApenasCasesJson();
  }

  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });
    console.log("\n=================================================");
    console.log("  Selecione a base de testes para o benchmark:");
    console.log(`  1: Rodar apenas 'cases.json'`);
    console.log(`  2: Rodar TODOS os arquivos 'cases*.json' (${allCasesFiles.join(", ")})`);
    console.log("=================================================\n");

    rl.question("Escolha (1 ou 2, padrão: 1): ", (resposta) => {
      rl.close();
      const escolha = resposta.trim();
      if (escolha === "2") {
        console.log("\n📂 Carregando todos os casos cumulativamente...\n");
        resolve(carregarTodosOsCasos());
      } else {
        console.log("\n📂 Carregando apenas 'cases.json'...\n");
        resolve(carregarApenasCasesJson());
      }
    });
  });
}

// ══════════════════════════════════════════
// CONVERSÃO: cases.json → formato do /api/benchmark
// ══════════════════════════════════════════
function converterParaFormatoWorker(cases) {
  return cases.map((c, i) => {
    const esperado = [...new Set(
      c.expected_entities 
        ? c.expected_entities.map(e => e.tipo) 
        : (c.labels || []).map(e => e.subcategory || e.category)
    )];
    let domain = c.domain;
    let profile = c.profile;
    if (!domain && !profile && c.labels) {
      domain = "health";
      profile = "clinical";
    }
    const categoria = `${domain || "auto"}/${profile || "generic"}`;
    return {
      id: i + 1,
      entrada: c.text,
      esperado: esperado,
      categoria: categoria
    };
  });
}

// ══════════════════════════════════════════
// ENVIO AO WORKER EM LOTES
// ══════════════════════════════════════════
async function enviarLote(endpoint, lote) {
  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ casos: lote }),
    signal: AbortSignal.timeout(120000)
  });

  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(`HTTP ${res.status}: ${txt.substring(0, 200)}`);
  }
  return res.json();
}

// ══════════════════════════════════════════
// EXECUÇÃO DO BENCHMARK
// ══════════════════════════════════════════
async function rodarBenchmark() {
  if (!ADMIN_SECRET) {
    console.error("❌ ADMIN_SECRET não definido!");
    console.error("   Use: set ADMIN_SECRET=sua_senha");
    process.exit(1);
  }

  console.log("🔍 Verificando conectividade com o worker...");
  try {
    const healthRes = await fetch(`${WORKER_URL}/api/health`, {
      signal: AbortSignal.timeout(5000)
    });
    if (!healthRes.ok) throw new Error(`Health check falhou: ${healthRes.status}`);
    const h = await healthRes.json();
    console.log(`✅ Worker conectado! NER Server: ${h.ner_server ? "🟢 ON" : "🔴 OFF"}`);
    if (!h.ner_server) {
      console.log("⚠️  NER desligado — benchmark rodará só com Regex (F1 menor).\n");
    }
  } catch (err) {
    console.error(`❌ Worker não acessível em ${WORKER_URL}`);
    console.error(`   Detalhes: ${err.message}`);
    process.exit(1);
  }

  const baseCases = await obterBaseCases();
  const casosFormatados = converterParaFormatoWorker(baseCases);

  console.log(`🚀 Executando Benchmark (${casosFormatados.length} casos, lotes de ${LOTE_TAMANHO})`);
  console.log(`📡 Worker: ${WORKER_URL}\n`);

  const endpoint = `${WORKER_URL}/api/benchmark?secret=${ADMIN_SECRET}`;
  const tStart = Date.now();

  const todosResultados = [];
  const falhasAcumuladas = [];
  const errosPorCategoria = {};  // categoria → count
  const fpPorTipoGlobal = {};
  const fnPorTipoGlobal = {};

  for (let i = 0; i < casosFormatados.length; i += LOTE_TAMANHO) {
    const lote = casosFormatados.slice(i, i + LOTE_TAMANHO);
    const numLote = Math.floor(i / LOTE_TAMANHO) + 1;
    const totalLotes = Math.ceil(casosFormatados.length / LOTE_TAMANHO);

    process.stdout.write(`  Lote ${numLote}/${totalLotes} (${lote.length} casos)... `);

    try {
      const data = await enviarLote(endpoint, lote);
      todosResultados.push(data.resumo);
      falhasAcumuladas.push(...(data.detalhes_falhas || []));
      
      // Agrega erros por categoria
      for (const [cat, count] of Object.entries(data.erros_por_categoria || {})) {
        errosPorCategoria[cat] = (errosPorCategoria[cat] || 0) + count;
      }
      
      // Agrega FP/FN por tipo
      for (const [tipo, count] of Object.entries(data.falsos_positivos_por_tipo || {})) {
        fpPorTipoGlobal[tipo] = (fpPorTipoGlobal[tipo] || 0) + count;
      }
      for (const [tipo, count] of Object.entries(data.falsos_negativos_por_tipo || {})) {
        fnPorTipoGlobal[tipo] = (fnPorTipoGlobal[tipo] || 0) + count;
      }
      
      console.log(`✅ F1=${data.resumo.f1.toFixed(4)} | acertos=${data.resumo.acertos}/${data.resumo.total_casos}`);
    } catch (err) {
      console.log(`❌ ${err.message}`);
    }
  }

  const duration = Date.now() - tStart;

  // ══════════════════════════════════════════
  // AGREGAÇÃO DOS RESULTADOS
  // ══════════════════════════════════════════
  const totalCasos = todosResultados.reduce((s, r) => s + (r.total_casos || 0), 0);
  const totalAcertos = todosResultados.reduce((s, r) => s + (r.acertos || 0), 0);
  const totalFalhas = todosResultados.reduce((s, r) => s + (r.falhas || 0), 0);

  const f1Final = totalCasos > 0
    ? todosResultados.reduce((s, r) => s + (r.f1 || 0) * (r.total_casos || 0), 0) / totalCasos
    : 0;
  const precisionFinal = totalCasos > 0
    ? todosResultados.reduce((s, r) => s + (r.precision || 0) * (r.total_casos || 0), 0) / totalCasos
    : 0;
  const recallFinal = totalCasos > 0
    ? todosResultados.reduce((s, r) => s + (r.recall || 0) * (r.total_casos || 0), 0) / totalCasos
    : 0;

  // ══════════════════════════════════════════
  // RELATÓRIO GERAL
  // ══════════════════════════════════════════
  console.log("\n════════════════ RESULTS OVERALL ════════════════");
  console.log(`Tempo Total     : ${duration} ms (${(duration/1000).toFixed(1)}s)`);
  console.log(`Total de Casos  : ${totalCasos}`);
  console.log(`Acertos Exatos  : ${totalAcertos} (${((totalAcertos / totalCasos) * 100).toFixed(2)}%)`);
  console.log(`Falhas          : ${totalFalhas}`);
  console.log(`Precisão Geral  : ${(precisionFinal * 100).toFixed(2)}%`);
  console.log(`Recall Geral    : ${(recallFinal * 100).toFixed(2)}%`);
  console.log(`F1 Score Geral  : ${f1Final.toFixed(4)} (${(f1Final * 100).toFixed(2)}%)`);
  console.log("══════════════════════════════════════════════════");

  // ══════════════════════════════════════════
  // ERROS POR DOMÍNIO (agrupado)
  // ══════════════════════════════════════════
  const errosPorDominio = {};
  for (const [cat, count] of Object.entries(errosPorCategoria)) {
    const dominio = cat.split("/")[0];
    errosPorDominio[dominio] = (errosPorDominio[dominio] || 0) + count;
  }

  if (Object.keys(errosPorDominio).length > 0) {
    console.log("\n📊 ERROS POR DOMÍNIO (visão macro):");
    console.log("─".repeat(60));
    console.log(`${"Domínio".padEnd(20)} ${"Erros".padStart(8)} ${"Barra Visual".padStart(20)}`);
    console.log("─".repeat(60));
    const maxErros = Math.max(...Object.values(errosPorDominio));
    for (const [dom, count] of Object.entries(errosPorDominio).sort((a, b) => b[1] - a[1])) {
      const barLen = Math.round((count / maxErros) * 20);
      const bar = "█".repeat(barLen);
      console.log(`${dom.toUpperCase().padEnd(20)} ${String(count).padStart(8)} ${bar}`);
    }
  }

  // ══════════════════════════════════════════
  // ERROS POR SUBCATEGORIA (domain/profile)
  // ══════════════════════════════════════════
  if (Object.keys(errosPorCategoria).length > 0) {
    console.log("\n📋 ERROS POR SUBCATEGORIA (domain/profile):");
    console.log("─".repeat(70));
    console.log(`${"Categoria".padEnd(35)} ${"Erros".padStart(8)} ${"% do Total".padStart(12)}`);
    console.log("─".repeat(70));
    const sorted = Object.entries(errosPorCategoria).sort((a, b) => b[1] - a[1]);
    for (const [cat, count] of sorted) {
      const pct = ((count / totalFalhas) * 100).toFixed(1);
      console.log(`${cat.padEnd(35)} ${String(count).padStart(8)} ${(pct + "%").padStart(12)}`);
    }
  }

  // ══════════════════════════════════════════
  // FALSOS POSITIVOS POR TIPO
  // ══════════════════════════════════════════
  if (Object.keys(fpPorTipoGlobal).length > 0) {
    console.log("\n⚠️  FALSOS POSITIVOS POR TIPO (detectou mas não esperava):");
    console.log("─".repeat(60));
    console.log(`${"Tipo".padEnd(24)} ${"Ocorrências".padStart(12)} ${"Impacto".padStart(20)}`);
    console.log("─".repeat(60));
    for (const [tipo, count] of Object.entries(fpPorTipoGlobal).sort((a, b) => b[1] - a[1])) {
      const cor = count > 10 ? "🔴" : count > 5 ? "🟡" : "🟢";
      const bar = "●".repeat(Math.min(count, 20));
      console.log(`${tipo.padEnd(24)} ${String(count).padStart(12)} ${cor} ${bar}`);
    }
  }

  // ══════════════════════════════════════════
  // FALSOS NEGATIVOS POR TIPO
  // ══════════════════════════════════════════
  if (Object.keys(fnPorTipoGlobal).length > 0) {
    console.log("\n❌ FALSOS NEGATIVOS POR TIPO (esperava mas não detectou):");
    console.log("─".repeat(60));
    console.log(`${"Tipo".padEnd(24)} ${"Ocorrências".padStart(12)} ${"Impacto".padStart(20)}`);
    console.log("─".repeat(60));
    for (const [tipo, count] of Object.entries(fnPorTipoGlobal).sort((a, b) => b[1] - a[1])) {
      const cor = count > 10 ? "🔴" : count > 5 ? "🟡" : "🟢";
      const bar = "●".repeat(Math.min(count, 20));
      console.log(`${tipo.padEnd(24)} ${String(count).padStart(12)} ${cor} ${bar}`);
    }
  }

  // ══════════════════════════════════════════
  // TOP FALHAS AGRUPADAS POR CATEGORIA
  // ══════════════════════════════════════════
  if (falhasAcumuladas.length > 0) {
    console.log("\n🔍 TOP FALHAS AGRUPADAS POR CATEGORIA:");
    console.log("═".repeat(70));
    
    // Agrupa falhas por categoria
    const falhasPorCategoria = {};
    for (const f of falhasAcumuladas) {
      const cat = f.categoria || "SEM_CATEGORIA";
      if (!falhasPorCategoria[cat]) falhasPorCategoria[cat] = [];
      falhasPorCategoria[cat].push(f);
    }
    
    // Ordena categorias por número de falhas
    const categoriasOrdenadas = Object.entries(falhasPorCategoria)
      .sort((a, b) => b[1].length - a[1].length);
    
    for (const [cat, falhas] of categoriasOrdenadas.slice(0, 5)) {
      console.log(`\n📁 ${cat} (${falhas.length} falhas):`);
      console.log("─".repeat(70));
      for (const f of falhas.slice(0, 3)) {
        const entrada = String(f.entrada || "").substring(0, 55);
        console.log(`  #${f.id} | "${entrada}${entrada.length >= 55 ? '...' : ''}"`);
        if (f.fp_tipos?.length) console.log(`       FP: ${f.fp_tipos.join(", ")}`);
        if (f.fn_tipos?.length) console.log(`       FN: ${f.fn_tipos.join(", ")}`);
      }
      if (falhas.length > 3) {
        console.log(`  ... e mais ${falhas.length - 3} falhas nesta categoria`);
      }
    }
  }

  // ══════════════════════════════════════════
  // RECOMENDAÇÕES AUTOMÁTICAS
  // ══════════════════════════════════════════
  console.log("\n💡 RECOMENDAÇÕES AUTOMÁTICAS:");
  console.log("─".repeat(70));
  
  if (f1Final >= 0.95) {
    console.log("✅ F1 ≥ 0.95 — Modelo em excelente estado para produção.");
  } else if (f1Final >= 0.90) {
    console.log(`🟡 F1 = ${f1Final.toFixed(2)} — Aceitável, mas revisar tipos com mais falhas.`);
  } else {
    console.log(`🔴 F1 = ${f1Final.toFixed(2)} — Modelo precisa de ajuste antes de produção.`);
  }
  
  // Identifica tipos críticos
  const fnCriticos = Object.entries(fnPorTipoGlobal).filter(([, n]) => n >= 5);
  if (fnCriticos.length > 0) {
    const top = fnCriticos.sort((a, b) => b[1] - a[1]).slice(0, 3);
    const tipos = top.map(([t, n]) => `${t}(${n})`).join(", ");
    console.log(`🔴 Falsos negativos altos em: ${tipos}.`);
    console.log(`   → Gere mais casos sintéticos focados nesses tipos.`);
  }
  
  const fpCriticos = Object.entries(fpPorTipoGlobal).filter(([, n]) => n >= 5);
  if (fpCriticos.length > 0) {
    const top = fpCriticos.sort((a, b) => b[1] - a[1]).slice(0, 3);
    const tipos = top.map(([t, n]) => `${t}(${n})`).join(", ");
    console.log(`🟡 Falsos positivos altos em: ${tipos}.`);
    console.log(`   → Revisar filtros pós-inferência no worker.`);
  }
  
  if (recallFinal < precisionFinal - 0.05) {
    console.log("🟡 Recall menor que precisão — modelo está sendo conservador.");
    console.log("   → Pode estar deixando PII passar.");
  } else if (precisionFinal < recallFinal - 0.05) {
    console.log("🟡 Precisão menor que recall — modelo está sendo agressivo.");
    console.log("   → Pode estar mascarando texto que não é PII.");
  }

  // ══════════════════════════════════════════
  // REGRESSION GUARD
  // ══════════════════════════════════════════
  const F1_REFERENCIA = 0.97;
  const F1_MINIMO = F1_REFERENCIA - 0.005;
  console.log(`\n🔒 Regressão Guard: F1 obtido (${f1Final.toFixed(4)}) vs mínimo (${F1_MINIMO.toFixed(4)})`);

  if (f1Final < F1_MINIMO) {
    console.error("❌ REGRESSÃO DE BENCHMARK DETECTADA! F1 abaixo da cota de tolerância.");
    process.exit(1);
  } else {
    console.log("✅ Benchmark aprovado! F1 dentro dos limites de produção.");
  }
}

rodarBenchmark().catch(err => {
  console.error("❌ Erro fatal:", err);
  process.exit(1);
});