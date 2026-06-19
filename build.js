// build.js: Script de empacotamento offline para gerar o arquivo único dist/worker.js
// compatível com o painel web da Cloudflare (Quick Edit)
import fs from "fs";
import path from "path";

const filesToBundle = [
  "src/utils/helpers.js",
  "src/utils/patterns.js",
  "src/utils/metrics.js",
  "src/adapters/inputAdapter.js",
  "src/resolvers/contextResolver.js",
  "src/router/profileRouter.js",
  "src/router/domainRouter.js",
  "src/pipelines/detectionPipeline.js",
  "src/layers/promotionLayer.js",
  "src/layers/policyLayer.js",
  "src/engines/maskEngine.js",
  "src/worker.js"
];

const outputDir = "./dist";
const outputFile = path.join(outputDir, "worker.js");

function bundle() {
  console.log("📦 Iniciando empacotamento do MascaraAI...");

  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir);
  }

  let bundledContent = "";
  bundledContent += `// ══════════════════════════════════════════\n`;
  bundledContent += `// MascaraAI — Compilado Único para Cloudflare Dashboard v3.1\n`;
  bundledContent += `// Gerado em: ${new Date().toISOString()}\n`;
  bundledContent += `// ══════════════════════════════════════════\n\n`;

  for (const filePath of filesToBundle) {
    console.log(`Reading: ${filePath}`);
    const absolutePath = path.resolve(filePath);
    if (!fs.existsSync(absolutePath)) {
      console.error(`Erro: Arquivo não encontrado: ${filePath}`);
      process.exit(1);
    }

    let fileContent = fs.readFileSync(absolutePath, "utf8");

    // Processamento do conteúdo do arquivo
    const lines = fileContent.split("\n");
    const processedLines = lines.filter(line => {
      const trimmed = line.trim();
      
      // Remove importações locais de outros arquivos do projeto (ex: import ... from "./...")
      if (trimmed.startsWith("import ") && (trimmed.includes("./") || trimmed.includes("../"))) {
        return false;
      }
      
      // Remove a importação do crypto do Node, pois Workers já possuem crypto global nativo
      if (trimmed.startsWith("import ") && trimmed.includes("crypto") && trimmed.includes("from")) {
        return false;
      }
      
      return true;
    });

    bundledContent += `// ── SEÇÃO: ${path.basename(filePath)} ───────────────────\n`;
    // Remove qualquer exportação padrão intermediária para não conflitar com a do worker.js final
    let moduleBody = processedLines.join("\n");
    if (filePath !== "src/worker.js") {
      moduleBody = moduleBody.replace(/export\s+default\s+/g, "");
    }
    
    bundledContent += moduleBody + "\n\n";
  }

  fs.writeFileSync(outputFile, bundledContent, "utf8");
  console.log(`\n✅ Sucesso! Arquivo único gerado em: ${outputFile}`);
  console.log(`Copie o conteúdo deste arquivo e cole diretamente no Quick Edit do painel do Cloudflare.`);
}

bundle();
