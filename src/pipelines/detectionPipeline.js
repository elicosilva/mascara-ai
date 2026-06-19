// Detection Pipeline: Orquestra a execução paralela de Regex e chamadas NER (BERT/GLiNER)
import { PII_PATTERNS, protegerChavesJSON, restaurarChavesJSON } from "../utils/patterns.js";
import { gerarToken } from "../utils/helpers.js";

// Lista de tipos leves para o modo regexMode === "light"
const LIGHT_TYPES = new Set(["EMAIL", "TELEFONE", "CPF", "CARTAO", "CHAVE_PIX", "IP_ADDRESS", "NOME_PESSOA", "PROFISSIONAL_SAUDE"]);

export class DetectionPipeline {
  static async run(text, env, strategy, metrics) {
    if (!text || text.trim().length < 3) {
      return { text, regexDetections: [], nerDetections: [], totalEncontrado: 0 };
    }

    const regexMode = strategy.regexMode || "heavy";
    const nerMode = strategy.nerMode || "standard";

    // 1. Executa a detecção por REGEX (Mede tempo)
    metrics.start("regex");
    const regexResult = await this.detectarPII(text, regexMode);
    metrics.stop("regex");

    // 2. Executa a detecção por NER (Mede tempo e possui short-circuit)
    metrics.start("ner");
    let nerResult = { encontrados: [], nerOk: false };
    
    // Otimização de Performance: Se nerMode for minimal, ignora a chamada ao servidor NER (BERT)
    // para evitar a latência de rede em arquivos de Log ou prontuários de triagem simples.
    // Short-circuit: só chama o NER se houver letras no texto (se for apenas números/símbolos, pula)
    const temLetras = /[A-Za-zÀ-Úa-zà-ú]/.test(text);
    const glinerUrl = (env && env.GLINER_URL) || "https://ecosilva-mascara-ai-ner.hf.space";
    if (nerMode !== "minimal" && glinerUrl && temLetras) {
      const localEnv = { ...env, GLINER_URL: glinerUrl };
      nerResult = await this.detectarNER(text, localEnv);
    }
    metrics.stop("ner");

    return {
      textoLimpo: regexResult.textoLimpo,
      regexDetections: regexResult.deteccoes,
      nerDetections: nerResult.encontrados,
      nerOk: nerResult.nerOk
    };
  }

  // Detecção via expressões regulares
  static async detectarPII(texto, regexMode) {
    const textoProtegido = protegerChavesJSON(texto);
    const deteccoes = [];
    const tokensMap = {};
    let textoLimpo = textoProtegido;

    // Filtra padrões com base no modo (light vs heavy)
    const activePatterns = PII_PATTERNS.filter(p => {
      if (regexMode === "light") {
        return LIGHT_TYPES.has(p.type);
      }
      return true;
    });

    for (const p of activePatterns) {
      const flags = p.regex.flags.includes("g") ? p.regex.flags : p.regex.flags + "g";
      const regexGlobal = new RegExp(p.regex.source, flags);

      for (const m of [...textoProtegido.matchAll(regexGlobal)]) {
        const valor = m[1] !== undefined ? m[1] : m[0];
        if (!valor || !p.validate(valor)) continue;

        const chave = String(valor).trim().toLowerCase();
        if (tokensMap[chave]) continue;

        const token = await gerarToken(p.type, valor);
        tokensMap[chave] = { token, valor, tipo: p.type };
        deteccoes.push({ tipo: p.type, token, valor });
      }
    }

    // Ordena os valores do maior para o menor para evitar substituição de substrings internas primeiro
    const sortedItems = Object.values(tokensMap).sort((a, b) => b.valor.length - a.valor.length);
    const deteccoesEfetuadas = [];

    for (const item of sortedItems) {
      if (!textoLimpo.includes(item.valor)) continue;
      textoLimpo = textoLimpo.split(item.valor).join(item.token);
      
      const originalDet = deteccoes.find(d => d.valor === item.valor);
      if (originalDet) {
        deteccoesEfetuadas.push(originalDet);
      }
    }

    // Remove tokens aninhados causados por colisões de regex
    textoLimpo = textoLimpo.replace(
      /\u27E6PII:[^\u27E6\u27E7]*\u27E6PII:[A-Z_]+:[0-9A-F]{8}\u27E7[^\u27E6\u27E7]*\u27E7/g,
      (match) => {
        const interno = match.match(/\u27E6PII:[A-Z_]+:[0-9A-F]{8}\u27E7/);
        return interno ? interno[0] : match;
      }
    );

    textoLimpo = restaurarChavesJSON(textoLimpo);

    return { textoLimpo, deteccoes: deteccoesEfetuadas };
  }

  // Detecção via servidor NER externo (BERTimbau / leNER / GLiNER)
  static async detectarNER(texto, env) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 15000); // Timeout de 15 segundos (compatível com processamento de CPU de IA)

      const headers = {
        "Content-Type": "application/json",
        "X-API-Key": env.GLINER_API_KEY || "",
      };
      if (env.GLINER_API_KEY) {
        headers["Authorization"] = `Bearer ${env.GLINER_API_KEY}`;
      }

      const res = await fetch(`${env.GLINER_URL}/detect`, {
        method: "POST",
        headers: headers,
        body: JSON.stringify({ text: texto }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!res.ok) {
        return { encontrados: [], nerOk: false };
      }

      const data = await res.json();
      const encontrados = (data.encontrados || []).map(e => ({
        tipo: e.tipo,
        valor: e.valor
      }));

      return { encontrados, nerOk: true };
    } catch (e) {
      // Falha silenciosa para garantir resiliência caso o servidor NER caia
      return { encontrados: [], nerOk: false };
    }
  }
}
