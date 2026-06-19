// Input Adapter: Normaliza e resolve o texto de entrada a partir de vários formatos de payload (texto, JSON estruturado, n8n, etc.)

export class InputAdapter {
  static parse(rawBody) {
    let text = "";
    let context = {};
    let policy = {};

    if (!rawBody) {
      return { text: "", context, policy };
    }

    // Se já for um objeto parsed (passado diretamente por outro middleware do worker)
    if (typeof rawBody === "object") {
      return this.extractFromObject(rawBody);
    }

    // Tenta fazer parse do JSON se for string
    if (typeof rawBody === "string") {
      const trimmed = rawBody.trim();
      if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
        try {
          const parsedObj = JSON.parse(trimmed);
          return this.extractFromObject(parsedObj);
        } catch {
          // Se falhar o parse, trata como string simples
          text = rawBody;
        }
      } else {
        text = rawBody;
      }
    }

    return { text, context, policy };
  }

  static extractFromObject(obj) {
    let text = "";
    const context = obj.context || {};
    const policy = obj.policy || {};

    // Prioridade de resolução de payload:
    // 1. payload.text
    // 2. payload.mensagem
    // 3. text
    // 4. mensagem
    // 5. corpo serializado (excluindo chaves de controle para evitar redundância)
    if (obj.payload && typeof obj.payload === "object") {
      if (obj.payload.text !== undefined) {
        text = String(obj.payload.text);
      } else if (obj.payload.mensagem !== undefined) {
        text = String(obj.payload.mensagem);
      }
    }

    if (!text) {
      if (obj.text !== undefined) {
        text = String(obj.text);
      } else if (obj.mensagem !== undefined) {
        text = String(obj.mensagem);
      }
    }

    // Se não encontrou campo de texto direto, faz o fallback para o corpo serializado
    if (!text) {
      // Clona para remover as chaves de controle (context e policy) antes de serializar
      const cleanObj = { ...obj };
      delete cleanObj.context;
      delete cleanObj.policy;
      
      // Se sobrou apenas um objeto vazio ou nada, retorna em branco
      if (Object.keys(cleanObj).length === 0) {
        text = "";
      } else {
        text = JSON.stringify(cleanObj);
      }
    }

    return { text, context, policy };
  }
}
